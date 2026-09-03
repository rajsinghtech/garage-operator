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

package v1beta2

import (
	"context"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rajsinghtech/garage-operator/internal/storagecontract"
)

const (
	testNamespace         = "default"
	storeClusterRefName   = "store"
	testLocalValue        = "local"
	testRemoteSiteName    = "site-b"
	testNodeLocalPoolName = "local-700"
	testMetadataHostPath  = "/var/lib/garage/metadata"
	testHandleName        = "handle"
	testRPCSecretKey      = "mesh"
	testSiteA             = "site-a"
	testMetadataValue     = "metadata"
	testDiskValue         = "disk"
	testOldValue          = "old"
	testNewValue          = "new"
	testChangedValue      = "changed"
	testCleanupFinalizer  = "example.test/cleanup"
	testEdgePayloadEnv    = "GARAGE_EDGE_PAYLOAD"
	testLegacyVolumeKey   = "example.com/legacy"
	testSSDValue          = "ssd"
)

func TestGarageClusterDefaulter_PreservesExplicitZeroReplicas(t *testing.T) {
	d := &GarageClusterDefaulter{}
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "zero-replicas", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Storage: &StorageSpec{
				Replicas: 0,
			},
			Gateway: &GatewaySpec{
				Replicas: 0,
			},
		},
	}

	if err := d.Default(context.Background(), cluster); err != nil {
		t.Fatalf("Default: %v", err)
	}

	if cluster.Spec.Storage.Replicas != 0 {
		t.Fatalf("storage replicas defaulted to %d, want explicit 0 preserved", cluster.Spec.Storage.Replicas)
	}
	if cluster.Spec.Gateway.Replicas != 0 {
		t.Fatalf("gateway replicas defaulted to %d, want explicit 0 preserved", cluster.Spec.Gateway.Replicas)
	}
}

func TestValidateManagedTierReplicasBoundsDerivedNames(t *testing.T) {
	for _, field := range []string{"spec.storage.replicas", "spec.gateway.replicas"} {
		if err := validateManagedTierReplicas(50, field); err != nil {
			t.Fatalf("%s rejected supported maximum: %v", field, err)
		}
		if err := validateManagedTierReplicas(51, field); err == nil || !strings.Contains(err.Error(), "at most 50") {
			t.Fatalf("%s accepted a replica count that can overflow derived names: %v", field, err)
		}
	}
}

func TestGarageClusterNameBoundsFollowOwnedWorkloadShape(t *testing.T) {
	auto := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("a", 50)},
		Spec:       GarageClusterSpec{Storage: &StorageSpec{Replicas: 50}},
	}
	if err := validateManagedGarageClusterName(auto); err != nil {
		t.Fatalf("50-character Auto cluster name rejected: %v", err)
	}
	auto.Name = strings.Repeat("a", 51)
	if err := validateManagedGarageClusterName(auto); err == nil || !strings.Contains(err.Error(), "Auto storage GarageNode") {
		t.Fatalf("cluster name that overflows <cluster>-storage-49-0 accepted: %v", err)
	}
	auto.Spec.Storage.Replicas = 10
	if err := validateManagedGarageClusterName(auto); err != nil {
		t.Fatalf("51-character Auto name with a one-digit highest ordinal rejected: %v", err)
	}
	auto.Spec.Storage.Replicas = 11
	if err := validateManagedGarageClusterName(auto); err == nil {
		t.Fatal("51-character Auto name with a two-digit highest ordinal was accepted")
	}

	nodeLocalOnly := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("n", 54)},
		Spec:       GarageClusterSpec{Storage: &StorageSpec{Replicas: 0}},
	}
	if err := validateManagedGarageClusterName(nodeLocalOnly); err != nil {
		t.Fatalf("54-character node-local-only shape was rejected by an Auto-only bound: %v", err)
	}
	nodeLocalOnly.Name = strings.Repeat("n", 55)
	if err := validateManagedGarageClusterName(nodeLocalOnly); err == nil || !strings.Contains(err.Error(), "headless") {
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

	edge := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("e", 52)},
		Spec:       GarageClusterSpec{Gateway: &GatewaySpec{Replicas: 50}},
	}
	if err := validateManagedGarageClusterName(edge); err != nil {
		t.Fatalf("52-character edge gateway name rejected: %v", err)
	}
	edge.Name = strings.Repeat("e", 53)
	if err := validateManagedGarageClusterName(edge); err == nil || !strings.Contains(err.Error(), "edge gateway StatefulSet Pod label") {
		t.Fatalf("edge gateway name that overflows its Pod selector label accepted: %v", err)
	}
	edge.Spec.Gateway.Replicas = 10
	if err := validateManagedGarageClusterName(edge); err != nil {
		t.Fatalf("53-character edge gateway with one-digit highest ordinal rejected: %v", err)
	}
	edge.Spec.Gateway.Replicas = 11
	if err := validateManagedGarageClusterName(edge); err == nil {
		t.Fatal("53-character edge gateway with a two-digit highest ordinal was accepted")
	}

	manualDefault := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("m", 54)},
		Spec: GarageClusterSpec{
			LayoutPolicy: layoutPolicyAuto,
			Storage:      &StorageSpec{Replicas: 11, LayoutPolicy: layoutPolicyManual},
		},
	}
	if err := validateManagedGarageClusterName(manualDefault); err != nil {
		t.Fatalf("per-tier Manual storage was rejected by the Auto name bound: %v", err)
	}
	manualDefault.Name = strings.Repeat("s", 51)
	manualDefault.Spec.LayoutPolicy = layoutPolicyManual
	manualDefault.Spec.Storage.LayoutPolicy = layoutPolicyAuto
	if err := validateManagedGarageClusterName(manualDefault); err == nil {
		t.Fatal("per-tier Auto storage escaped the derived GarageNode Pod-name check")
	}
}

func TestGarageClusterNameUpdateGrandfathersOnlyNonExpandingTransitions(t *testing.T) {
	oldCluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("a", 51), Namespace: testNamespace},
		Spec:       GarageClusterSpec{Storage: &StorageSpec{Replicas: 11}},
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
	scaleDown.Spec.Storage.Replicas = 10
	if grandfather, err := validateManagedGarageClusterNameUpdate(oldCluster, scaleDown); err != nil || grandfather {
		t.Fatalf("scale-down to a valid shape should pass strict validation: grandfather=%v err=%v", grandfather, err)
	}

	scaleUp := oldCluster.DeepCopy()
	scaleUp.Spec.Storage.Replicas = 12
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

func TestValidateGarageEnvironmentRejectsEveryCredentialOverridePath(t *testing.T) {
	reserved := []string{
		garageConfigFileEnv,
		garageRPCSecretEnv, garageRPCSecretFileEnv,
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
			if err := validateGarageEnvironment(nil, []corev1.EnvFromSource{{Prefix: prefix}}, "spec.gateway"); err == nil {
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

func TestGarageClusterValidator_GrandfathersOnlyMonotonicLegacyEnvironmentCleanup(t *testing.T) {
	oneGi := resource.MustParse("1Gi")
	base := func() *GarageCluster {
		return &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "legacy-env", Namespace: testNamespace},
			Spec: GarageClusterSpec{
				Storage: &StorageSpec{
					Replicas: 1, Metadata: &VolumeConfig{Size: &oneGi}, Data: &VolumeConfig{Size: &oneGi},
					PodTemplate: PodTemplate{
						Env:     []corev1.EnvVar{{Name: garageConfigFileEnv, Value: "/tmp/legacy.toml"}},
						EnvFrom: []corev1.EnvFromSource{{Prefix: ""}},
					},
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
	if got := strings.Join(warnings, " "); !strings.Contains(got, "operator ignores them") {
		t.Fatalf("legacy environment update lacked a migration warning: %v", warnings)
	}

	mutated := oldCluster.DeepCopy()
	mutated.Spec.Storage.Env[0].Value = "/tmp/different.toml"
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
	changedOverlong.Spec.Storage.Env[len(changedOverlong.Spec.Storage.Env)-1].Value = testChangedValue
	if _, err := validator.ValidateUpdate(context.Background(), overlong, changedOverlong); err == nil ||
		!strings.Contains(err.Error(), "may only shrink") {
		t.Fatalf("mutation within an overlong released environment was accepted: %v", err)
	}
}

func TestGarageClusterValidator_GrandfathersNewSchemaBoundsAndTierShapes(t *testing.T) {
	oneGi := resource.MustParse("1Gi")
	validator := &GarageClusterValidator{}

	overReplica := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy-replicas", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Storage:     &StorageSpec{Replicas: 51, Metadata: &VolumeConfig{Size: &oneGi}, Data: &VolumeConfig{Size: &oneGi}},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	metadataUpdate := overReplica.DeepCopy()
	metadataUpdate.Finalizers = []string{testCleanupFinalizer}
	if warnings, err := validator.ValidateUpdate(context.Background(), overReplica, metadataUpdate); err != nil {
		t.Fatalf("metadata update on released over-bound replicas was rejected: %v", err)
	} else if !strings.Contains(strings.Join(warnings, " "), "temporarily tolerated") {
		t.Fatalf("over-bound replica update lacked a migration warning: %v", warnings)
	}
	increase := overReplica.DeepCopy()
	increase.Spec.Storage.Replicas = 52
	if _, err := validator.ValidateUpdate(context.Background(), overReplica, increase); err == nil ||
		!strings.Contains(err.Error(), "may only remain unchanged or decrease") {
		t.Fatalf("growth above the released replica bound was accepted: %v", err)
	}
	decrease := overReplica.DeepCopy()
	decrease.Spec.Storage.Replicas = 50
	validationCopy := decrease.DeepCopy()
	if _, err := neutralizeLegacyGarageClusterReplicaBoundsForValidation(overReplica, validationCopy); err != nil {
		t.Fatalf("monotonic reduction into the replica bound was rejected: %v", err)
	}

	conflicting := overReplica.DeepCopy()
	conflicting.Spec.Storage.Replicas = 1
	conflicting.Spec.ConnectTo = &ConnectToConfig{ClusterRef: &ClusterReference{Name: storeClusterRefName}}
	conflictingUpdate := conflicting.DeepCopy()
	conflictingUpdate.Finalizers = []string{testCleanupFinalizer}
	if warnings, err := validator.ValidateUpdate(context.Background(), conflicting, conflictingUpdate); err != nil {
		t.Fatalf("finalizer update on a released conflicting tier shape was rejected: %v", err)
	} else if !strings.Contains(strings.Join(warnings, " "), "ownership model") {
		t.Fatalf("conflicting tier shape lacked a migration warning: %v", warnings)
	}
	conflictingMutation := conflicting.DeepCopy()
	conflictingMutation.Spec.Image = "example.com/garage:new"
	if _, err := validator.ValidateUpdate(context.Background(), conflicting, conflictingMutation); err == nil ||
		!strings.Contains(err.Error(), "byte-for-byte unchanged") {
		t.Fatalf("spec mutation on a released conflicting tier shape was accepted: %v", err)
	}

	missingVolumes := overReplica.DeepCopy()
	missingVolumes.Spec.Storage.Replicas = 1
	missingVolumes.Spec.Storage.Metadata = nil
	missingVolumesUpdate := missingVolumes.DeepCopy()
	missingVolumesUpdate.Finalizers = []string{testCleanupFinalizer}
	if warnings, err := validator.ValidateUpdate(context.Background(), missingVolumes, missingVolumesUpdate); err != nil {
		t.Fatalf("finalizer update on released missing default volumes was rejected: %v", err)
	} else if !strings.Contains(strings.Join(warnings, " "), "without both metadata and data") {
		t.Fatalf("missing default volumes lacked a migration warning: %v", warnings)
	}
}

func TestEffectiveRPCIdentitySourceCoversEveryTierShape(t *testing.T) {
	base := &GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "store", Namespace: "garage"}}
	defaultSource := "secret:garage/store-rpc-secret:rpc-secret"
	if got := effectiveRPCIdentitySource(base); got != defaultSource {
		t.Fatalf("default source = %q, want %q", got, defaultSource)
	}

	semanticDefault := base.DeepCopy()
	semanticDefault.Spec.Network.RPCSecretRef = &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "store-rpc-secret"},
		Optional:             func() *bool { v := true; return &v }(),
	}
	if got := effectiveRPCIdentitySource(semanticDefault); got != defaultSource {
		t.Fatalf("semantic default source = %q, want %q", got, defaultSource)
	}

	poolOnly := validDaemonSetCluster()
	poolOnly.Name, poolOnly.Namespace = "store", "garage"
	if got := effectiveRPCIdentitySource(poolOnly); got != defaultSource {
		t.Fatalf("pool-only source = %q, want %q", got, defaultSource)
	}

	handle := base.DeepCopy()
	handle.Spec.ConnectTo = &ConnectToConfig{
		AdminAPIEndpoint:    "http://external.garage.svc:3903",
		AdminTokenSecretRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "admin"}},
	}
	if got := effectiveRPCIdentitySource(handle); got != "" {
		t.Fatalf("Admin-only management handle source = %q, want empty", got)
	}
	handle.Spec.ConnectTo.RPCSecretRef = &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "external-rpc"}, Key: testRPCSecretKey,
	}
	if got, want := effectiveRPCIdentitySource(handle), "secret:garage/external-rpc:mesh"; got != want {
		t.Fatalf("management handle source = %q, want %q", got, want)
	}

	gateway := base.DeepCopy()
	gateway.Spec.Gateway = &GatewaySpec{Replicas: 1}
	gateway.Spec.ConnectTo = &ConnectToConfig{ClusterRef: &ClusterReference{Name: "storage"}}
	if got, want := effectiveRPCIdentitySource(gateway), "cluster:garage/storage"; got != want {
		t.Fatalf("gateway clusterRef source = %q, want %q", got, want)
	}
	gateway.Spec.ConnectTo.RPCSecretRef = &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "shared"}, Key: testRPCSecretKey,
	}
	if got, want := effectiveRPCIdentitySource(gateway), "secret:garage/shared:mesh"; got != want {
		t.Fatalf("gateway direct source = %q, want %q", got, want)
	}
	gateway.Spec.Network.RPCSecretRef = &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "authoritative"}, Key: "rpc",
	}
	if got, want := effectiveRPCIdentitySource(gateway), "secret:garage/authoritative:rpc"; got != want {
		t.Fatalf("network source did not take precedence: got %q, want %q", got, want)
	}
}

func TestGarageClusterValidator_StagesLegacyRPCSecretMigrationWithoutRotatingWorkloads(t *testing.T) {
	oneGi := resource.MustParse("1Gi")
	oldCluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy-rpc-env", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Storage: &StorageSpec{
				Replicas: 1,
				Metadata: &VolumeConfig{Size: &oneGi},
				Data:     &VolumeConfig{Size: &oneGi},
				PodTemplate: PodTemplate{Env: []corev1.EnvVar{{
					Name: garageRPCSecretEnv, Value: strings.Repeat("a", 64),
				}}},
			},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	staged := oldCluster.DeepCopy()
	staged.Annotations = map[string]string{legacyRPCSecretMigrationAnnotation: stringTrue}
	staged.Spec.Network.RPCSecretRef = &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "verified-legacy-rpc"},
		Key:                  testRPCSecretKey,
	}
	warnings, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), oldCluster, staged)
	if err != nil {
		t.Fatalf("staging a fail-closed legacy RPC source was rejected: %v", err)
	}
	if !warningContains(warnings, "keep every managed workload frozen") {
		t.Fatalf("staged migration lacked the workload-freeze warning: %v", warnings)
	}

	withoutOptIn := staged.DeepCopy()
	withoutOptIn.Annotations = nil
	if _, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), oldCluster, withoutOptIn); err == nil ||
		!strings.Contains(err.Error(), "identity source is immutable") {
		t.Fatalf("legacy RPC source change without explicit migration was accepted: %v", err)
	}

	rolled := staged.DeepCopy()
	rolled.Spec.Image = "example.invalid/garage:changed"
	if _, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), oldCluster, rolled); err == nil ||
		!strings.Contains(err.Error(), "identity source is immutable") {
		t.Fatalf("migration source staging also rolled a workload: %v", err)
	}

	removedTooSoon := staged.DeepCopy()
	removedTooSoon.Spec.Storage.Env = nil
	if _, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), oldCluster, removedTooSoon); err == nil ||
		!strings.Contains(err.Error(), "identity source is immutable") {
		t.Fatalf("single-step source change and legacy override removal was accepted: %v", err)
	}
}

func TestGarageClusterValidator_ManagementHandleRPCSourceCanAttachOnce(t *testing.T) {
	old := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testHandleName, Namespace: testNamespace},
		Spec: GarageClusterSpec{ConnectTo: &ConnectToConfig{
			AdminAPIEndpoint:    "http://external.garage.svc:3903",
			AdminTokenSecretRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "admin"}},
		}},
	}
	attached := old.DeepCopy()
	attached.Spec.ConnectTo.RPCSecretRef = &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "external-rpc"}, Key: testRPCSecretKey,
	}
	validator := &GarageClusterValidator{}
	if _, err := validator.ValidateUpdate(context.Background(), old, attached); err != nil {
		t.Fatalf("first management-handle RPC identity source was rejected: %v", err)
	}
	rotated := attached.DeepCopy()
	rotated.Spec.ConnectTo.RPCSecretRef.Name = "different-rpc"
	if _, err := validator.ValidateUpdate(context.Background(), attached, rotated); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("management-handle RPC identity rotation error = %v, want immutable rejection", err)
	}
}

func TestGarageClusterValidator_RemoteClusterOwnershipIsUnambiguous(t *testing.T) {
	cluster := &GarageCluster{Spec: GarageClusterSpec{
		Zone: testLocalValue,
		RemoteClusters: []RemoteClusterConfig{
			{Name: testRemoteSiteName, Zone: "remote-b"},
			{Name: testRemoteSiteName, Zone: "remote-c"},
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
	cluster.Spec.RemoteClusters[1].Zone = testLocalValue
	if err := cluster.validateRemoteClusters(); err != nil {
		t.Fatalf("all-sites inventory with one local-zone entry rejected: %v", err)
	}
}

func TestGarageClusterValidator_WarnsWhenFederatedDeletionDefaultsToDestroy(t *testing.T) {
	cluster := validDaemonSetCluster()
	cluster.Spec.DeletionPolicy = DeletionPolicyDestroy
	cluster.Spec.RemoteClusters = []RemoteClusterConfig{{
		Name: testRemoteSiteName, Zone: testRemoteSiteName,
		Connection: RemoteClusterConnection{AdminAPIEndpoint: "https://site-b.example"},
	}}
	warnings, err := cluster.validateGarageCluster()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, warning := range warnings {
		if strings.Contains(warning, "deletionPolicy is Destroy") {
			found = true
		}
	}
	if !found {
		t.Fatalf("federated Destroy warning missing: %v", warnings)
	}
}

func TestGarageClusterValidator_DrainDeleteRequiresCompletedPreparation(t *testing.T) {
	const drainedNodeID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cluster := validDaemonSetCluster()
	cluster.Name = testSiteA
	cluster.Namespace = testNamespace
	cluster.UID = "cluster-uid"
	cluster.Generation = 4
	cluster.Spec.DeletionPolicy = DeletionPolicyDrain
	cluster.Spec.Replication.ConsistencyMode = consistencyModeConsistent
	cluster.Status.Conditions = []metav1.Condition{{
		Type: storageRolloutReadyCondition, Status: metav1.ConditionTrue,
		Reason: "Converged", ObservedGeneration: cluster.Generation,
	}}
	cluster.Status.Health = &ClusterHealth{
		Status: healthStatusHealthy, Healthy: true, Available: true,
		StorageNodes: 3, StorageNodesOK: 3,
		Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256,
	}
	validator := &GarageClusterValidator{}
	if _, err := validator.ValidateDelete(context.Background(), cluster); err == nil ||
		!strings.Contains(err.Error(), "prepared deletion") {
		t.Fatalf("unprepared Drain deletion was accepted: %v", err)
	}

	cluster.Annotations = map[string]string{drainPreparationAnnotation: stringTrue}
	cluster.Status.StorageDrain = &StorageDrainStatus{
		Actor: StorageDrainActorStatus{
			APIVersion: GroupVersion.String(), Kind: "GarageCluster",
			Namespace: cluster.Namespace, Name: cluster.Name, UID: string(cluster.UID),
		},
		TransactionID: "txn",
		TargetHash: storagecontract.TargetHash(
			[]string{drainedNodeID}, []string{drainedNodeID},
		),
		StartedAt:          metav1.Now(),
		RoleRemovalNodeIDs: []string{drainedNodeID}, RemovedStorageNodeIDs: []string{drainedNodeID},
	}
	if _, err := validator.ValidateDelete(context.Background(), cluster); err == nil {
		t.Fatal("incomplete cluster storage-drain proof authorized deletion")
	}
	completedAt := metav1.Now()
	cluster.Status.StorageDrain.CompletedAt = &completedAt
	if _, err := validator.ValidateDelete(context.Background(), cluster); err != nil {
		t.Fatalf("completed exact cluster drain preparation was rejected: %v", err)
	}
}

func TestGarageClusterValidator_DrainAnnotationRequiresExplicitPolicy(t *testing.T) {
	cluster := validDaemonSetCluster()
	cluster.Annotations = map[string]string{drainPreparationAnnotation: stringTrue}
	if _, err := cluster.validateGarageCluster(); err == nil || !strings.Contains(err.Error(), "explicit spec.deletionPolicy: Drain") {
		t.Fatalf("drain preparation without explicit Drain policy was accepted: %v", err)
	}
	cluster.Spec.DeletionPolicy = DeletionPolicyDrain
	cluster.Spec.RemoteClusters = []RemoteClusterConfig{{
		Name: testRemoteSiteName, Zone: testRemoteSiteName,
		Connection: RemoteClusterConnection{AdminAPIEndpoint: "https://site-b.example"},
	}}
	cluster.Spec.LayoutManagement = &LayoutManagementConfig{
		Drain: &StorageDrainConfig{UnverifiedPeersPolicy: StorageDrainUnverifiedPeersAssumeConsistent},
	}
	if _, err := cluster.validateGarageCluster(); err != nil {
		t.Fatalf("valid Drain preparation request was rejected: %v", err)
	}
}

func TestGarageClusterDeepCopyDoesNotAliasStorageRollout(t *testing.T) {
	original := &GarageCluster{Status: GarageClusterStatus{StorageRollout: &StorageRolloutStatus{
		NodeLocalPoolName: testLocalValue, KubernetesNodeName: "worker-a", GarageNodeUID: "node-uid",
		WorkloadUID: "ds-uid", KubernetesNodeUID: "worker-uid", PreviousPodUID: testOldValue, DesiredPodSpecHash: "hash",
	}}}
	copy := original.DeepCopy()
	copy.Status.StorageRollout.NodeLocalPoolName = "archive"
	if original.Status.StorageRollout.NodeLocalPoolName != testLocalValue {
		t.Fatal("DeepCopy aliased status.storageRollout")
	}
}

func TestGarageClusterValidator_AllowsZeroReplicas(t *testing.T) {
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "zero-replicas", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Storage: &StorageSpec{
				Replicas: 0,
				Metadata: &VolumeConfig{},
				Data:     &VolumeConfig{Type: VolumeTypeEmptyDir},
			},
			Gateway: &GatewaySpec{
				Replicas: 0,
			},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}

	if _, err := cluster.validateGarageCluster(); err != nil {
		t.Fatalf("validateGarageCluster rejected zero replicas: %v", err)
	}
}

func TestGarageClusterValidator_FactorChangeRequiresAtomicPurgeRequest(t *testing.T) {
	old := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "factor", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Storage: &StorageSpec{
				Replicas: 2,
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
	atomic.Annotations = map[string]string{"garage.rajsingh.info/purge-cluster-layout": "factor=2"}
	if _, err := validator.ValidateUpdate(context.Background(), old, atomic); err != nil {
		t.Fatalf("matching atomic factor migration request rejected: %v", err)
	}
}

func TestGarageClusterValidator_RejectsManualToAutoTransition(t *testing.T) {
	v := &GarageClusterValidator{}
	old := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "tx", Namespace: testNamespace, Generation: 1},
		Spec: GarageClusterSpec{
			LayoutPolicy: layoutPolicyManual,
			Storage: &StorageSpec{
				Replicas: 1,
				Metadata: &VolumeConfig{},
				Data:     &VolumeConfig{Type: VolumeTypeEmptyDir},
			},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	markGarageClusterDrainReady(old)
	newer := old.DeepCopy()
	newer.Spec.LayoutPolicy = layoutPolicyAuto

	if _, err := v.ValidateUpdate(context.Background(), old, newer); err == nil {
		t.Fatalf("ValidateUpdate accepted Manual→Auto transition, want error")
	}

	// Manual→Manual (or Manual with empty new) is fine.
	sameManual := old.DeepCopy()
	if _, err := v.ValidateUpdate(context.Background(), old, sameManual); err != nil {
		t.Fatalf("ValidateUpdate rejected Manual→Manual: %v", err)
	}
}

func TestEffectiveStorageLayoutPolicy(t *testing.T) {
	cases := []struct {
		name        string
		clusterPol  string
		storage     *StorageSpec
		wantStorage string
	}{
		{"storage override wins", layoutPolicyAuto, &StorageSpec{LayoutPolicy: layoutPolicyManual}, layoutPolicyManual},
		{"storage unset -> cluster default", layoutPolicyAuto, &StorageSpec{}, layoutPolicyAuto},
		{"no storage tier -> cluster default", layoutPolicyManual, nil, layoutPolicyManual},
	}
	for _, tc := range cases {
		c := &GarageCluster{Spec: GarageClusterSpec{LayoutPolicy: tc.clusterPol, Storage: tc.storage}}
		if got := c.EffectiveStorageLayoutPolicy(); got != tc.wantStorage {
			t.Errorf("%s: EffectiveStorageLayoutPolicy()=%q want %q", tc.name, got, tc.wantStorage)
		}
	}
}

// Per-tier policy: storage can go Manual while the cluster (and thus gateway)
// stays Auto, but storage Manual->Auto is still one-way.
func TestGarageClusterValidator_RejectsStorageManualToAuto(t *testing.T) {
	v := &GarageClusterValidator{}
	old := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "tier-tx", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			LayoutPolicy: layoutPolicyAuto,
			Storage: &StorageSpec{
				Replicas:     1,
				LayoutPolicy: layoutPolicyManual,
				Metadata:     &VolumeConfig{},
				Data:         &VolumeConfig{Type: VolumeTypeEmptyDir},
			},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	// storage Manual -> Auto must be rejected even though cluster policy is Auto.
	toAuto := old.DeepCopy()
	toAuto.Spec.Storage.LayoutPolicy = layoutPolicyAuto
	if _, err := v.ValidateUpdate(context.Background(), old, toAuto); err == nil {
		t.Fatalf("ValidateUpdate accepted storage Manual→Auto, want error")
	}
	// Clearing the override falls back to cluster Auto — also a Manual->Auto.
	cleared := old.DeepCopy()
	cleared.Spec.Storage.LayoutPolicy = ""
	if _, err := v.ValidateUpdate(context.Background(), old, cleared); err == nil {
		t.Fatalf("ValidateUpdate accepted clearing storage Manual override (-> cluster Auto), want error")
	}
	// storage Manual -> Manual is fine.
	same := old.DeepCopy()
	if _, err := v.ValidateUpdate(context.Background(), old, same); err != nil {
		t.Fatalf("ValidateUpdate rejected storage Manual→Manual: %v", err)
	}
}

func TestGarageClusterValidator_AllowsAutoToManualTransition(t *testing.T) {
	v := &GarageClusterValidator{}
	old := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "tx", Namespace: testNamespace, Generation: 1},
		Spec: GarageClusterSpec{
			LayoutPolicy: layoutPolicyAuto,
			Storage: &StorageSpec{
				Replicas: 1,
				Metadata: &VolumeConfig{},
				Data:     &VolumeConfig{Type: VolumeTypeEmptyDir},
			},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	markGarageClusterDrainReady(old)
	newer := old.DeepCopy()
	newer.Spec.LayoutPolicy = layoutPolicyManual

	if _, err := v.ValidateUpdate(context.Background(), old, newer); err != nil {
		t.Fatalf("ValidateUpdate rejected Auto→Manual: %v", err)
	}
}

func TestGarageClusterValidator_RejectsMinNodesHealthyWhenAllReplicasPaused(t *testing.T) {
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "paused", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Storage: &StorageSpec{
				Replicas: 0,
				Metadata: &VolumeConfig{},
				Data:     &VolumeConfig{Type: VolumeTypeEmptyDir},
			},
			Replication:      &ReplicationConfig{Factor: 1},
			LayoutManagement: &LayoutManagementConfig{MinNodesHealthy: 1},
		},
	}

	if err := cluster.validateLayoutManagement(); err == nil {
		t.Fatalf("validateLayoutManagement accepted minNodesHealthy with zero replicas")
	}
}

// TestGarageClusterValidator_RejectsGatewayMetadataEmptyDirMisconfig verifies
// the gateway-tier metadata VolumeConfig is now validated the same way storage
// is — an EmptyDir volume carrying PVC-only fields is rejected (issue #219).
func TestGarageClusterValidator_RejectsGatewayMetadataEmptyDirMisconfig(t *testing.T) {
	sc := "fast"
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Gateway: &GatewaySpec{
				Replicas: 2,
				Metadata: &VolumeConfig{
					Type:             VolumeTypeEmptyDir,
					StorageClassName: &sc,
				},
			},
			ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: storeClusterRefName}},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}

	if _, err := cluster.validateGarageCluster(); err == nil {
		t.Fatalf("validateGarageCluster accepted EmptyDir gateway metadata with storageClassName, want error")
	}
}

// TestGarageClusterValidator_WarnsGatewayMetadataEmptyDir verifies the
// node-identity warning is emitted for an EmptyDir gateway metadata volume,
// matching the storage-tier behavior (issue #219).
func TestGarageClusterValidator_WarnsGatewayMetadataEmptyDir(t *testing.T) {
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Gateway: &GatewaySpec{
				Replicas: 2,
				Metadata: &VolumeConfig{Type: VolumeTypeEmptyDir},
			},
			ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: storeClusterRefName}},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}

	warnings, err := cluster.validateGarageCluster()
	if err != nil {
		t.Fatalf("validateGarageCluster: unexpected error %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "gateway.metadata.type=EmptyDir") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected gateway.metadata EmptyDir identity warning, got %v", warnings)
	}
}

func TestGarageClusterValidator_RejectsIgnoredGatewayMetadataFields(t *testing.T) {
	validEdge := func() *GarageCluster {
		return &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: testNamespace},
			Spec: GarageClusterSpec{
				Gateway:     &GatewaySpec{Replicas: 1, Metadata: &VolumeConfig{}},
				ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: storeClusterRefName}},
				Replication: &ReplicationConfig{Factor: 1},
			},
		}
	}

	paths := validEdge()
	paths.Spec.Gateway.Metadata.Paths = []DataPath{{Path: "/metadata-is-not-data"}}
	if _, err := paths.validateGarageCluster(); err == nil || !strings.Contains(err.Error(), "gateway.metadata.paths") {
		t.Fatalf("gateway metadata paths were not rejected explicitly: %v", err)
	}

	claimTemplate := validEdge()
	claimTemplate.Spec.Gateway.Metadata.VolumeClaimTemplateSpec = &corev1.PersistentVolumeClaimSpec{}
	if _, err := claimTemplate.validateGarageCluster(); err == nil || !strings.Contains(err.Error(), "volumeClaimTemplateSpec") {
		t.Fatalf("unimplemented gateway claim template was not rejected explicitly: %v", err)
	}

	manual := validEdge()
	manual.Spec.LayoutPolicy = layoutPolicyManual
	if _, err := manual.validateGarageCluster(); err == nil || !strings.Contains(err.Error(), "not applied") {
		t.Fatalf("ignored Manual gateway metadata was not rejected explicitly: %v", err)
	}
}

func TestGarageClusterValidator_RejectsUnsupportedDefaultStorageClaimTemplates(t *testing.T) {
	claimTemplate := &corev1.PersistentVolumeClaimSpec{}
	cluster := &GarageCluster{}

	for _, tc := range []struct {
		name  string
		field string
		check func() error
	}{
		{
			name:  testMetadataValue,
			field: "spec.storage.metadata.volumeClaimTemplateSpec",
			check: func() error {
				return cluster.validateVolumeConfig(&VolumeConfig{VolumeClaimTemplateSpec: claimTemplate}, "spec.storage.metadata")
			},
		},
		{
			name:  "data",
			field: "spec.storage.data.volumeClaimTemplateSpec",
			check: func() error {
				return cluster.validateVolumeConfig(&VolumeConfig{VolumeClaimTemplateSpec: claimTemplate}, "spec.storage.data")
			},
		},
		{
			name:  "data path",
			field: "spec.storage.data.paths[0].volume.volumeClaimTemplateSpec",
			check: func() error {
				return validateDataPathVolumeConfig(
					&DataPathVolumeConfig{VolumeClaimTemplateSpec: claimTemplate},
					"spec.storage.data.paths[0].volume",
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

func TestGarageClusterValidator_RejectsInvalidPersistentVolumeSelectors(t *testing.T) {
	badKey := &metav1.LabelSelector{MatchLabels: map[string]string{"not a label key": testDiskValue}}
	if err := (&GarageCluster{}).validateVolumeConfig(
		&VolumeConfig{Selector: badKey}, "spec.storage.metadata",
	); err == nil || !strings.Contains(err.Error(), "spec.storage.metadata.selector") {
		t.Fatalf("invalid storage selector was not rejected with its field path: %v", err)
	}

	badOperator := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: "disk.example.com/type", Operator: metav1.LabelSelectorOperator("Invalid"), Values: []string{"ssd"},
	}}}
	if err := validateDataPathVolumeConfig(
		&DataPathVolumeConfig{Selector: badOperator}, "spec.storage.data.paths[0].volume",
	); err == nil || !strings.Contains(err.Error(), "spec.storage.data.paths[0].volume.selector") {
		t.Fatalf("invalid data-path selector operator was not rejected with its field path: %v", err)
	}

	edge := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid-gateway-selector", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Gateway:     &GatewaySpec{Replicas: 1, Metadata: &VolumeConfig{Selector: badOperator}},
			ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: storeClusterRefName}},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	if _, err := edge.validateGarageCluster(); err == nil ||
		!strings.Contains(err.Error(), "spec.gateway.metadata.selector") {
		t.Fatalf("invalid gateway selector was not rejected before PVC reconciliation: %v", err)
	}
}

func TestGarageClusterValidator_GrandfathersOnlyUnchangedClaimTemplates(t *testing.T) {
	oneGi := resource.MustParse("1Gi")
	legacyTemplate := &corev1.PersistentVolumeClaimSpec{
		AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
	}
	base := func() *GarageCluster {
		return &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "legacy-template", Namespace: testNamespace},
			Spec: GarageClusterSpec{
				Storage: &StorageSpec{
					Replicas: 1,
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
	manualCreate.Spec.Storage.LayoutPolicy = layoutPolicyManual
	if _, err := manualCreate.validateGarageCluster(); err == nil ||
		!strings.Contains(err.Error(), "volumeClaimTemplateSpec") {
		t.Fatalf("new Manual shape bypassed claim-template rejection: %v", err)
	}
}

func TestGarageClusterValidator_GrandfathersLegacyGatewayClaimTemplateOnlyForRemoval(t *testing.T) {
	oneGi := resource.MustParse("1Gi")
	legacy := &corev1.PersistentVolumeClaimSpec{
		AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
	}
	old := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy-edge-template", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Gateway: &GatewaySpec{Replicas: 1, Metadata: &VolumeConfig{
				Size: &oneGi, VolumeClaimTemplateSpec: legacy,
			}},
			ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: storeClusterRefName}},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	removed := old.DeepCopy()
	removed.Spec.Gateway.Metadata.VolumeClaimTemplateSpec = nil
	warnings, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), old, removed)
	if err != nil {
		t.Fatalf("removal of a never-applied live edge claim template was rejected: %v", err)
	}
	if strings.Contains(strings.Join(warnings, " "), "legacy unsupported claim template") {
		t.Fatalf("removing the legacy edge field should not retain its compatibility warning: %v", warnings)
	}
}

func TestGarageClusterValidator_GrandfathersLegacyManualGatewayMetadataOnlyForRemoval(t *testing.T) {
	oneGi := resource.MustParse("1Gi")
	old := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy-manual-gateway", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			LayoutPolicy: layoutPolicyManual,
			Storage:      &StorageSpec{Replicas: 0},
			Gateway:      &GatewaySpec{Replicas: 1, Metadata: &VolumeConfig{Size: &oneGi}},
			Replication:  &ReplicationConfig{Factor: 1},
		},
	}

	unchanged := old.DeepCopy()
	unchanged.Spec.ImagePullPolicy = corev1.PullAlways
	warnings, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), old, unchanged)
	if err != nil {
		t.Fatalf("unrelated update with unchanged legacy Manual gateway metadata was rejected: %v", err)
	}
	if !strings.Contains(strings.Join(warnings, " "), "temporarily tolerated") {
		t.Fatalf("unchanged legacy Manual gateway metadata did not emit a migration warning: %v", warnings)
	}

	legacyClaimTemplate := old.DeepCopy()
	legacyClaimTemplate.Spec.Gateway.Metadata.VolumeClaimTemplateSpec = &corev1.PersistentVolumeClaimSpec{
		AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
	}
	removeOnlyClaimTemplate := legacyClaimTemplate.DeepCopy()
	removeOnlyClaimTemplate.Spec.Gateway.Metadata.VolumeClaimTemplateSpec = nil
	if _, err := (&GarageClusterValidator{}).ValidateUpdate(
		context.Background(), legacyClaimTemplate, removeOnlyClaimTemplate,
	); err != nil {
		t.Fatalf("legacy Manual gateway claim-template field could not be removed independently: %v", err)
	}

	removed := old.DeepCopy()
	removed.Spec.Gateway.Metadata = nil
	if _, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), old, removed); err != nil {
		t.Fatalf("legacy Manual gateway metadata removal was rejected: %v", err)
	}

	changed := old.DeepCopy()
	twoGi := resource.MustParse("2Gi")
	changed.Spec.Gateway.Metadata.Size = &twoGi
	if _, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), old, changed); err == nil ||
		!strings.Contains(err.Error(), "not applied") {
		t.Fatalf("legacy Manual gateway metadata mutation was accepted: %v", err)
	}

	created := old.DeepCopy()
	created.Spec.Gateway.Metadata = nil
	created.Spec.Gateway.Metadata = &VolumeConfig{Size: &oneGi}
	if _, err := created.validateGarageCluster(); err == nil || !strings.Contains(err.Error(), "not applied") {
		t.Fatalf("new Manual gateway metadata was accepted: %v", err)
	}
}

func TestDefaultStorageVolumeTopologyCannotChangeDuringZeroToLiveTransition(t *testing.T) {
	oneGi := resource.MustParse("1Gi")
	oldSelector := &metav1.LabelSelector{MatchLabels: map[string]string{testDiskValue: testOldValue}}
	newSelector := &metav1.LabelSelector{MatchLabels: map[string]string{testDiskValue: testNewValue}}
	old := &GarageCluster{Spec: GarageClusterSpec{Storage: &StorageSpec{
		Replicas: 0,
		Metadata: &VolumeConfig{Size: &oneGi, Selector: oldSelector},
		Data:     &VolumeConfig{Size: &oneGi},
	}}}
	newer := old.DeepCopy()
	newer.Spec.Storage.Replicas = 1
	newer.Spec.Storage.Metadata.Selector = newSelector
	if err := validateDefaultPoolVolumeUpdate(old, newer); err == nil || !strings.Contains(err.Error(), selectorJSONField) {
		t.Fatalf("0->N plus selector change was accepted: %v", err)
	}

	atZero := old.DeepCopy()
	atZero.Spec.Storage.Metadata.Selector = newSelector
	if err := validateDefaultPoolVolumeUpdate(old, atZero); err != nil {
		t.Fatalf("separate zero-replica template edit was rejected: %v", err)
	}
}

func TestDefaultStorageDataSourceRefCannotChangeAfterCreate(t *testing.T) {
	group := "kopiur.example.io"
	oneGi := resource.MustParse("1Gi")
	dataSize := resource.MustParse("10Gi")
	old := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "restore", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Storage: &StorageSpec{
				Replicas:           1,
				AllowDataSourceRef: true,
				DataSourceRef:      &corev1.TypedObjectReference{APIGroup: &group, Kind: "Restore", Name: "old-restore"},
				Metadata:           &VolumeConfig{Size: &oneGi},
				Data:               &VolumeConfig{Size: &dataSize},
			},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	changed := old.DeepCopy()
	changed.Spec.Storage.DataSourceRef.Name = "new-restore"
	if err := validateDefaultPoolVolumeUpdate(old, changed); err == nil || !strings.Contains(err.Error(), "dataSourceRef") {
		t.Fatalf("live data source change was accepted: %v", err)
	}
	if _, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), old, changed); err == nil || !strings.Contains(err.Error(), "dataSourceRef") {
		t.Fatalf("webhook accepted live data source change: %v", err)
	}

	zero := old.DeepCopy()
	zero.Spec.Storage.Replicas = 0
	zeroChanged := zero.DeepCopy()
	zeroChanged.Spec.Storage.DataSourceRef.Name = "new-restore"
	if err := validateDefaultPoolVolumeUpdate(zero, zeroChanged); err == nil || !strings.Contains(err.Error(), "immutable after GarageCluster creation") {
		t.Fatalf("data source change while the default group is stopped was accepted: %v", err)
	}
	if _, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), zero, zeroChanged); err == nil || !strings.Contains(err.Error(), "immutable after GarageCluster creation") {
		t.Fatalf("webhook accepted data source change while the default group is stopped: %v", err)
	}
}

func TestGarageClusterValidator_GatewayMetadataSelectorSupportsEdgeAndUnified(t *testing.T) {
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"disk.example.com/name": "gateway"}}
	edge := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Gateway: &GatewaySpec{Replicas: 1, Metadata: &VolumeConfig{
				Selector: selector,
			}},
			ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: storeClusterRefName}},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	if _, err := edge.validateGarageCluster(); err != nil {
		t.Fatalf("edge gateway metadata selector rejected: %v", err)
	}

	unified := edge.DeepCopy()
	unified.Name = "unified"
	unified.Spec.ConnectTo = nil
	oneGi := resource.MustParse("1Gi")
	unified.Spec.Storage = &StorageSpec{
		Replicas: 1,
		Metadata: &VolumeConfig{Size: &oneGi},
		Data:     &VolumeConfig{Type: VolumeTypeEmptyDir},
	}
	if _, err := unified.validateGarageCluster(); err != nil {
		t.Fatalf("unified gateway metadata selector rejected: %v", err)
	}
}

func TestGarageClusterValidator_EdgeGatewayMetadataChangesRequireZeroReplicas(t *testing.T) {
	oneGi := resource.MustParse("1Gi")
	twoGi := resource.MustParse("2Gi")
	old := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "edge-resize", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Gateway:     &GatewaySpec{Replicas: 1, Metadata: &VolumeConfig{Size: &oneGi}},
			ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: storeClusterRefName}},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
	newer := old.DeepCopy()
	newer.Spec.Gateway.Metadata.Size = &twoGi
	if _, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), old, newer); err == nil ||
		!strings.Contains(err.Error(), "scale spec.gateway.replicas to 0") {
		t.Fatalf("live edge metadata change was not rejected with the serialized procedure: %v", err)
	}

	// Combining the first scale-to-zero step with the template edit would let
	// reconciliation recreate an immutable StatefulSet while its old Pods/PVCs
	// are still retiring. The old generation being live is the relevant fence.
	combined := old.DeepCopy()
	combined.Spec.Gateway.Replicas = 0
	combined.Spec.Gateway.Metadata.Size = &twoGi
	if _, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), old, combined); err == nil ||
		!strings.Contains(err.Error(), "scale spec.gateway.replicas to 0") {
		t.Fatalf("combined N→0 plus edge metadata change was not rejected: %v", err)
	}

	// The opposite 0->N boundary is equally important: retained PVCs selected
	// under the old template must not be silently reused while activating roles.
	zeroOld := old.DeepCopy()
	zeroOld.Spec.Gateway.Replicas = 0
	zeroOld.Spec.Gateway.Metadata.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{testDiskValue: testOldValue}}
	activateChanged := zeroOld.DeepCopy()
	activateChanged.Spec.Gateway.Replicas = 1
	activateChanged.Spec.Gateway.Metadata.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{testDiskValue: testNewValue}}
	if _, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), zeroOld, activateChanged); err == nil ||
		!strings.Contains(err.Error(), "scale spec.gateway.replicas to 0") {
		t.Fatalf("combined 0→N plus edge metadata change was accepted: %v", err)
	}

	old.Spec.Gateway.Replicas = 0
	newer.Spec.Gateway.Replicas = 0
	if _, err := (&GarageClusterValidator{}).ValidateUpdate(context.Background(), old, newer); err != nil {
		t.Fatalf("zero-replica edge metadata change rejected: %v", err)
	}
}

// TestGarageClusterValidator_WarnsSharedStorageRPCAddr guards the multi-replica
// storage tier sharing one rpc_public_addr (reachable cross-region at one pod).
func TestGarageClusterValidator_WarnsSharedStorageRPCAddr(t *testing.T) {
	base := func(addr string) *GarageCluster {
		return &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "stg", Namespace: testNamespace},
			Spec: GarageClusterSpec{
				Storage: &StorageSpec{
					Replicas:      3,
					RPCPublicAddr: addr,
					Metadata:      &VolumeConfig{Type: VolumeTypeEmptyDir},
					Data:          &VolumeConfig{Type: VolumeTypeEmptyDir},
				},
				Replication: &ReplicationConfig{Factor: 2},
			},
		}
	}
	hasWarn := func(c *GarageCluster) bool {
		warnings, err := c.validateGarageCluster()
		if err != nil {
			t.Fatalf("validateGarageCluster: unexpected error %v", err)
		}
		for _, w := range warnings {
			if strings.Contains(w, "spec.storage.rpcPublicAddr is a single address") {
				return true
			}
		}
		return false
	}
	if !hasWarn(base("storage.example.ts.net:3901")) {
		t.Fatal("expected shared-storage-rpcaddr warning for multi-replica storage without {ordinal}")
	}
	if hasWarn(base("storage-{ordinal}.example.ts.net:3901")) {
		t.Fatal("must NOT warn when {ordinal} placeholder is present")
	}
	if hasWarn(base("")) {
		t.Fatal("must NOT warn when rpcPublicAddr is unset")
	}
}

func TestGarageClusterValidator_WarnsSharedGatewayRPCAddr(t *testing.T) {
	mk := func(addr string) *GarageCluster {
		return &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: testNamespace},
			Spec: GarageClusterSpec{
				Storage:     &StorageSpec{Replicas: 1, Metadata: &VolumeConfig{}, Data: &VolumeConfig{Type: VolumeTypeEmptyDir}},
				Gateway:     &GatewaySpec{Replicas: 2, RPCPublicAddr: addr},
				Replication: &ReplicationConfig{Factor: 1},
			},
		}
	}
	hasSharedWarning := func(t *testing.T, c *GarageCluster) bool {
		t.Helper()
		warnings, err := c.validateGarageCluster()
		if err != nil {
			t.Fatalf("validateGarageCluster: unexpected error %v", err)
		}
		for _, w := range warnings {
			if strings.Contains(w, "shared by all gateway pods") {
				return true
			}
		}
		return false
	}

	// Multi-pod gateway with a single shared addr (no {ordinal}) → warn.
	if !hasSharedWarning(t, mk("shared.example.ts.net:3901")) {
		t.Fatal("expected shared-gateway-rpcPublicAddr warning for a 2-replica gateway with no {ordinal}")
	}
	// Per-ordinal template → no warning.
	if hasSharedWarning(t, mk("gw-{ordinal}.example.ts.net:3901")) {
		t.Fatal("did not expect the warning when rpcPublicAddr uses an {ordinal} placeholder")
	}
}

func TestGarageClusterValidator_AcceptsManagementHandle(t *testing.T) {
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testHandleName, Namespace: testNamespace},
		Spec: GarageClusterSpec{
			ConnectTo: &ConnectToConfig{
				AdminAPIEndpoint:    "http://garage.garage.svc:3903",
				AdminTokenSecretRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "garage-admin"}, Key: "admin-token"},
			},
		},
	}
	if _, err := cluster.validateGarageCluster(); err != nil {
		t.Fatalf("validateGarageCluster rejected management handle: %v", err)
	}

	// clusterRef is also a valid Admin-API path.
	cluster.Spec.ConnectTo = &ConnectToConfig{ClusterRef: &ClusterReference{Name: storeClusterRefName}}
	if _, err := cluster.validateGarageCluster(); err != nil {
		t.Fatalf("validateGarageCluster rejected clusterRef management handle: %v", err)
	}
}

func TestGarageClusterValidator_GrandfathersOnlyMonotonicRemovalOfIgnoredVolumeFields(t *testing.T) {
	oneGi := resource.MustParse("1Gi")
	storageClass := "ignored-class"
	badSelector := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: testDiskValue, Operator: metav1.LabelSelectorOperator("LegacyInvalid"), Values: []string{testSSDValue},
	}}}
	base := func() *GarageCluster {
		return &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name: "legacy-volume", Namespace: testNamespace, Finalizers: []string{testCleanupFinalizer},
			},
			Spec: GarageClusterSpec{
				Storage: &StorageSpec{
					Replicas: 1, Metadata: &VolumeConfig{Size: &oneGi}, Data: &VolumeConfig{Size: &oneGi},
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
					Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{testDiskValue: testOldValue}},
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
						Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{testDiskValue: testOldValue}},
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
				cluster.Spec.Storage.Data.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{testDiskValue: testNewValue}}
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

func TestGarageClusterPodLabelOwnershipAcrossStorageAndGateway(t *testing.T) {
	const reserved = "garage.rajsingh.info/scale-target"
	oneGi := resource.MustParse("1Gi")
	storage := func() *GarageCluster {
		return &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "storage-labels", Namespace: testNamespace},
			Spec: GarageClusterSpec{
				Storage: &StorageSpec{
					Replicas: 1, Metadata: &VolumeConfig{Size: &oneGi}, Data: &VolumeConfig{Size: &oneGi},
					PodTemplate: PodTemplate{PodLabels: map[string]string{reserved: "disabled", "legacy invalid storage key": "storage-legacy"}},
				},
				Replication: &ReplicationConfig{Factor: 1},
			},
		}
	}
	gateway := func() *GarageCluster {
		return &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "gateway-labels", Namespace: testNamespace},
			Spec: GarageClusterSpec{
				Gateway: &GatewaySpec{
					Replicas: 1, Metadata: &VolumeConfig{},
					PodTemplate: PodTemplate{PodLabels: map[string]string{reserved: "disabled", "legacy invalid gateway key": "gateway-legacy"}},
				},
				ConnectTo:   &ConnectToConfig{ClusterRef: &ClusterReference{Name: storeClusterRefName}},
				Replication: &ReplicationConfig{Factor: 1},
			},
		}
	}

	for name, base := range map[string]func() *GarageCluster{"storage": storage, "gateway": gateway} {
		t.Run(name, func(t *testing.T) {
			validator := &GarageClusterValidator{}
			oldCluster := base()
			createCluster := oldCluster.DeepCopy()
			if createCluster.Spec.Storage != nil {
				delete(createCluster.Spec.Storage.PodLabels, "legacy invalid storage key")
			} else {
				delete(createCluster.Spec.Gateway.PodLabels, "legacy invalid gateway key")
			}
			if _, err := validator.ValidateCreate(context.Background(), createCluster); err == nil ||
				!strings.Contains(err.Error(), "operator-managed") {
				t.Fatalf("create accepted an operator-owned pod label: %v", err)
			}
			finalizerUpdate := oldCluster.DeepCopy()
			finalizerUpdate.Finalizers = []string{testCleanupFinalizer}
			warnings, err := validator.ValidateUpdate(context.Background(), oldCluster, finalizerUpdate)
			if err != nil {
				t.Fatalf("finalizer update was stranded by unchanged legacy pod labels: %v", err)
			}
			if got := strings.Join(warnings, " "); !strings.Contains(got, "ignored") {
				t.Fatalf("legacy pod labels did not emit ignored-value warnings: %v", warnings)
			}

			mutated := oldCluster.DeepCopy()
			if mutated.Spec.Storage != nil {
				mutated.Spec.Storage.PodLabels[reserved] = "different"
			} else {
				mutated.Spec.Gateway.PodLabels[reserved] = "different"
			}
			if _, err := validator.ValidateUpdate(context.Background(), oldCluster, mutated); err == nil {
				t.Fatal("operator-owned pod label mutation was accepted")
			}

			cleaned := oldCluster.DeepCopy()
			if cleaned.Spec.Storage != nil {
				cleaned.Spec.Storage.PodLabels = map[string]string{"example.com/media": "fast"}
			} else {
				cleaned.Spec.Gateway.PodLabels = map[string]string{"example.com/media": "edge"}
			}
			if _, err := validator.ValidateUpdate(context.Background(), oldCluster, cleaned); err != nil {
				t.Fatalf("legacy pod label cleanup was rejected: %v", err)
			}
		})
	}
}

func TestGarageClusterValidator_RejectsHandleWithoutAdminPath(t *testing.T) {
	// connectTo with only rpcSecretRef / bootstrapPeers gives no Admin API.
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testHandleName, Namespace: testNamespace},
		Spec: GarageClusterSpec{
			ConnectTo: &ConnectToConfig{
				RPCSecretRef:   &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "rpc"}},
				BootstrapPeers: []string{"deadbeef@1.2.3.4:3901"},
			},
		},
	}
	if _, err := cluster.validateGarageCluster(); err == nil {
		t.Fatal("validateGarageCluster accepted a handle with no Admin-API path, want error")
	}

	// adminApiEndpoint without a token is not enough.
	cluster.Spec.ConnectTo = &ConnectToConfig{AdminAPIEndpoint: "http://x:3903"}
	if _, err := cluster.validateGarageCluster(); err == nil {
		t.Fatal("validateGarageCluster accepted adminApiEndpoint without adminTokenSecretRef, want error")
	}
}

func TestGarageClusterValidator_PreservesEdgeGatewayRule(t *testing.T) {
	// gateway without storage AND without connectTo is still rejected.
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: testNamespace},
		Spec: GarageClusterSpec{
			Gateway: &GatewaySpec{Replicas: 1},
		},
	}
	if _, err := cluster.validateGarageCluster(); err == nil {
		t.Fatal("validateGarageCluster accepted gateway-only cluster without connectTo, want error")
	}
}

func TestGarageClusterValidator_RejectsStorageAndConnectToInEveryGatewayShape(t *testing.T) {
	for _, gateway := range []*GatewaySpec{nil, {Replicas: 1}} {
		cluster := &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "ambiguous", Namespace: testNamespace},
			Spec: GarageClusterSpec{
				Storage:   &StorageSpec{},
				Gateway:   gateway,
				ConnectTo: &ConnectToConfig{ClusterRef: &ClusterReference{Name: storeClusterRefName}},
			},
		}
		if _, err := cluster.validateGarageCluster(); err == nil ||
			!strings.Contains(err.Error(), "storage and spec.connectTo are mutually exclusive") {
			t.Fatalf("validateGarageCluster accepted ambiguous storage/connectTo shape (gateway=%v): %v", gateway != nil, err)
		}
	}
}

// zoneFrom (#294) validation. A bad label key is rejected outright — otherwise
// a typo is indistinguishable from "the label isn't set" and silently degrades
// to the cluster-wide zone. The rest are warnings for configurations that are
// legal but won't do what the author expects.
func TestGarageClusterValidator_ZoneFrom(t *testing.T) {
	base := func(mutate func(*GarageCluster)) *GarageCluster {
		size := resource.MustParse("10Gi")
		c := &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "zf", Namespace: testNamespace},
			Spec: GarageClusterSpec{
				Zone:     testSiteA,
				ZoneFrom: &ZoneSource{NodeLabel: "example.com/rack"},
				Storage: &StorageSpec{
					Replicas: 3,
					Metadata: &VolumeConfig{Size: &size},
					Data:     &VolumeConfig{Size: &size},
				},
				Replication: &ReplicationConfig{Factor: 3},
			},
		}
		if mutate != nil {
			mutate(c)
		}
		return c
	}

	hasWarning := func(warnings []string, substr string) bool {
		for _, w := range warnings {
			if strings.Contains(w, substr) {
				return true
			}
		}
		return false
	}

	t.Run("accepts a valid label key with no warnings", func(t *testing.T) {
		warnings, err := base(nil).validateGarageCluster()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hasWarning(warnings, "zoneFrom") {
			t.Fatalf("unexpected zoneFrom warning: %v", warnings)
		}
	})

	t.Run("rejects an invalid label key", func(t *testing.T) {
		_, err := base(func(c *GarageCluster) {
			c.Spec.ZoneFrom.NodeLabel = "not a valid key!"
		}).validateGarageCluster()
		if err == nil {
			t.Fatal("expected an error for an invalid label key")
		}
		if !strings.Contains(err.Error(), "not a valid label key") {
			t.Fatalf("error should explain the label key is invalid, got: %v", err)
		}
	})

	t.Run("warns that Manual layout never sees zoneFrom", func(t *testing.T) {
		warnings, err := base(func(c *GarageCluster) {
			c.Spec.LayoutPolicy = layoutPolicyManual
		}).validateGarageCluster()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !hasWarning(warnings, "no effect with layoutPolicy: Manual") {
			t.Fatalf("expected a Manual-mode warning, got %v", warnings)
		}
	})

	t.Run("warns when AtLeast(n) may exceed the distinct label values available", func(t *testing.T) {
		n := 3
		warnings, err := base(func(c *GarageCluster) {
			c.Spec.Replication.ZoneRedundancyMode = zoneRedundancyAtLeast
			c.Spec.Replication.ZoneRedundancyMinZones = &n
		}).validateGarageCluster()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !hasWarning(warnings, "at least 3 distinct values") {
			t.Fatalf("expected an AtLeast warning, got %v", warnings)
		}
	})

	t.Run("stays silent when zoneFrom is unset", func(t *testing.T) {
		warnings, err := base(func(c *GarageCluster) { c.Spec.ZoneFrom = nil }).validateGarageCluster()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hasWarning(warnings, "zoneFrom") {
			t.Fatalf("unexpected zoneFrom warning: %v", warnings)
		}
	})
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

func TestGarageClusterValidator_DataSourceRefRequiresOptInAndAutoStorage(t *testing.T) {
	group := "kopiur.example.io"
	quantity := func(value string) *resource.Quantity { parsed := resource.MustParse(value); return &parsed }
	validator := &GarageClusterValidator{}
	base := func() *GarageCluster {
		return &GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "restore", Namespace: testNamespace}, Spec: GarageClusterSpec{
			Storage:     &StorageSpec{Replicas: 1, Metadata: &VolumeConfig{Size: quantity("1Gi")}, Data: &VolumeConfig{Size: quantity("10Gi")}, DataSourceRef: &corev1.TypedObjectReference{APIGroup: &group, Kind: "Restore", Name: "restore"}},
			Replication: &ReplicationConfig{Factor: 1},
		}}
	}
	cluster := base()
	if _, err := validator.ValidateCreate(context.Background(), cluster); err == nil || !strings.Contains(err.Error(), "allowDataSourceRef") {
		t.Fatalf("data source without acknowledgement accepted: %v", err)
	}
	cluster.Spec.Storage.AllowDataSourceRef = true
	if _, err := validator.ValidateCreate(context.Background(), cluster); err != nil {
		t.Fatalf("acknowledged Auto data source rejected: %v", err)
	}
	cluster.Spec.Storage.LayoutPolicy = layoutPolicyManual
	if _, err := validator.ValidateCreate(context.Background(), cluster); err == nil || !strings.Contains(err.Error(), "Auto storage group") {
		t.Fatalf("Manual data source accepted: %v", err)
	}
	for name, mutate := range map[string]func(*GarageCluster){
		"missing metadata size": func(c *GarageCluster) { c.Spec.Storage.Metadata.Size = nil },
		"missing data size":     func(c *GarageCluster) { c.Spec.Storage.Data.Size = nil },
		"cross namespace": func(c *GarageCluster) {
			namespace := "other"
			c.Spec.Storage.DataSourceRef.Namespace = &namespace
		},
		"missing kind": func(c *GarageCluster) {
			c.Spec.Storage.DataSourceRef.Kind = ""
		},
		"selector": func(c *GarageCluster) {
			c.Spec.Storage.Data.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"disk.example.com/type": "ssd"}}
		},
		"invalid name": func(c *GarageCluster) {
			c.Spec.Storage.DataSourceRef.Name = "not a DNS name"
		},
		"core source": func(c *GarageCluster) {
			c.Spec.Storage.DataSourceRef.APIGroup = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base()
			candidate.Spec.Storage.AllowDataSourceRef = true
			mutate(candidate)
			if _, err := validator.ValidateCreate(context.Background(), candidate); err == nil {
				t.Fatalf("invalid data source reference accepted")
			}
		})
	}
}

func TestGarageClusterValidator_DataSourceRefDoesNotPermitDataClaimTemplate(t *testing.T) {
	group := "kopiur.example.io"
	quantity := func(value string) *resource.Quantity { parsed := resource.MustParse(value); return &parsed }
	cluster := &GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "restore", Namespace: testNamespace}, Spec: GarageClusterSpec{
		Storage:     &StorageSpec{Replicas: 1, AllowDataSourceRef: true, DataSourceRef: &corev1.TypedObjectReference{APIGroup: &group, Kind: "Restore", Name: "restore"}, Metadata: &VolumeConfig{Size: quantity("1Gi")}, Data: &VolumeConfig{Size: quantity("10Gi"), VolumeClaimTemplateSpec: &corev1.PersistentVolumeClaimSpec{DataSourceRef: &corev1.TypedObjectReference{Kind: "Restore", Name: "restore"}}}},
		Replication: &ReplicationConfig{Factor: 1},
	}}
	if _, err := (&GarageClusterValidator{}).ValidateCreate(context.Background(), cluster); err == nil || !strings.Contains(err.Error(), "volumeClaimTemplateSpec") {
		t.Fatalf("claim template carve-out accepted: %v", err)
	}
}

func TestGarageClusterValidator_DataSourceRefDoesNotPermitMetadataClaimTemplateSource(t *testing.T) {
	group := "kopiur.example.io"
	quantity := func(value string) *resource.Quantity { parsed := resource.MustParse(value); return &parsed }
	cluster := &GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "metadata-restore", Namespace: testNamespace}, Spec: GarageClusterSpec{
		Storage: &StorageSpec{
			Replicas:           1,
			AllowDataSourceRef: true,
			DataSourceRef:      &corev1.TypedObjectReference{APIGroup: &group, Kind: "Restore", Name: "restore"},
			Metadata: &VolumeConfig{Size: quantity("1Gi"), VolumeClaimTemplateSpec: &corev1.PersistentVolumeClaimSpec{
				DataSourceRef: &corev1.TypedObjectReference{APIGroup: &group, Kind: "Restore", Name: "restore"},
			}},
			Data: &VolumeConfig{Size: quantity("10Gi")},
		},
		Replication: &ReplicationConfig{Factor: 1},
	}}
	if _, err := (&GarageClusterValidator{}).ValidateCreate(context.Background(), cluster); err == nil || !strings.Contains(err.Error(), "volumeClaimTemplateSpec") {
		t.Fatalf("metadata data source claim-template escape hatch accepted: %v", err)
	}
}
