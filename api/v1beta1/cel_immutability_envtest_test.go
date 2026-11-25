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
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	v1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/testutil"
)

func TestCELIdentityImmutabilityWithoutWebhooks(t *testing.T) {
	binaryDir := testutil.FindEnvTestBinaryDir(
		os.Getenv("KUBEBUILDER_ASSETS"),
		filepath.Join("..", "..", "bin", "k8s"),
	)
	if binaryDir == "" {
		t.Skip("envtest binaries not available")
	}

	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
		BinaryAssetsDirectory: binaryDir,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest without webhooks: %v", err)
	}
	defer func() {
		if stopErr := env.Stop(); stopErr != nil {
			t.Errorf("stop envtest: %v", stopErr)
		}
	}()

	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme v1beta1: %v", err)
	}
	if err := v1beta2.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme v1beta2: %v", err)
	}
	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("create k8s client: %v", err)
	}

	ctx := context.Background()
	const ns = "default"
	nodeID1 := strings.Repeat("a", 64)
	nodeID2 := strings.Repeat("b", 64)

	t.Run("GarageBucket", func(t *testing.T) {
		b := &GarageBucket{
			ObjectMeta: metav1.ObjectMeta{Name: "cel-bucket", Namespace: ns},
			Spec: GarageBucketSpec{
				ClusterRef:  ClusterReference{Name: "c1", Namespace: ns},
				GlobalAlias: "alias-1",
			},
		}
		if err := k8sClient.Create(ctx, b); err != nil {
			t.Fatalf("create bucket: %v", err)
		}

		// Mutable update succeeds.
		valid := b.DeepCopy()
		valid.Spec.GlobalAlias = "alias-2"
		if err := k8sClient.Update(ctx, valid); err != nil {
			t.Fatalf("expected mutable bucket update allowed: %v", err)
		}

		// Changing clusterRef.name is rejected by CEL.
		badName := valid.DeepCopy()
		badName.Spec.ClusterRef.Name = "c2"
		if err := k8sClient.Update(ctx, badName); err == nil || !strings.Contains(err.Error(), "clusterRef.name is immutable") {
			t.Fatalf("expected clusterRef.name immutability error, got %v", err)
		}

		// Changing explicit clusterRef.namespace is rejected by CEL.
		badNS := valid.DeepCopy()
		badNS.Spec.ClusterRef.Namespace = "other"
		if err := k8sClient.Update(ctx, badNS); err == nil || !strings.Contains(err.Error(), "clusterRef.namespace is immutable") {
			t.Fatalf("expected clusterRef.namespace immutability error, got %v", err)
		}
	})

	t.Run("GarageKey", func(t *testing.T) {
		kNoImport := &GarageKey{
			ObjectMeta: metav1.ObjectMeta{Name: "cel-key-plain", Namespace: ns},
			Spec: GarageKeySpec{
				ClusterRef: ClusterReference{Name: "c1"},
				Name:       "key-one",
			},
		}
		if err := k8sClient.Create(ctx, kNoImport); err != nil {
			t.Fatalf("create key without importKey: %v", err)
		}

		valid := kNoImport.DeepCopy()
		valid.Spec.Name = "key-two"
		if err := k8sClient.Update(ctx, valid); err != nil {
			t.Fatalf("expected mutable key update allowed: %v", err)
		}

		addImport := valid.DeepCopy()
		addImport.Spec.ImportKey = &ImportKeyConfig{AccessKeyID: "GK0123456789abcdef01234567"}
		if err := k8sClient.Update(ctx, addImport); err == nil || !strings.Contains(err.Error(), "importKey is immutable") {
			t.Fatalf("expected adding importKey rejected, got %v", err)
		}

		badCluster := valid.DeepCopy()
		badCluster.Spec.ClusterRef.Name = "c2"
		if err := k8sClient.Update(ctx, badCluster); err == nil || !strings.Contains(err.Error(), "clusterRef.name is immutable") {
			t.Fatalf("expected clusterRef.name immutability error, got %v", err)
		}

		kImported := &GarageKey{
			ObjectMeta: metav1.ObjectMeta{Name: "cel-key-imported", Namespace: ns},
			Spec: GarageKeySpec{
				ClusterRef: ClusterReference{Name: "c1"},
				ImportKey: &ImportKeyConfig{
					AccessKeyID: "GK0123456789abcdef01234567",
					SecretRef:   &corev1.SecretReference{Name: "sec", Namespace: ns},
				},
			},
		}
		if err := k8sClient.Create(ctx, kImported); err != nil {
			t.Fatalf("create imported key: %v", err)
		}
		changeImport := kImported.DeepCopy()
		changeImport.Spec.ImportKey.AccessKeyID = "GKffffffffffffffffffffffff"
		if err := k8sClient.Update(ctx, changeImport); err == nil || !strings.Contains(err.Error(), "importKey is immutable") {
			t.Fatalf("expected changing importKey rejected, got %v", err)
		}
	})

	t.Run("GarageAdminToken", func(t *testing.T) {
		inc := true
		tok := &GarageAdminToken{
			ObjectMeta: metav1.ObjectMeta{Name: "cel-token", Namespace: ns},
			Spec: GarageAdminTokenSpec{
				ClusterRef: ClusterReference{Name: "c1"},
				SecretTemplate: &AdminTokenSecretTemplate{
					Name:            "tok-sec",
					TokenKey:        "admin-token",
					IncludeEndpoint: &inc,
				},
			},
		}
		if err := k8sClient.Create(ctx, tok); err != nil {
			t.Fatalf("create admin token: %v", err)
		}

		// Mutable labels/annotations succeed.
		valid := tok.DeepCopy()
		valid.Spec.SecretTemplate.Labels = map[string]string{"env": "dev"}
		if err := k8sClient.Update(ctx, valid); err != nil {
			t.Fatalf("expected secretTemplate labels update allowed: %v", err)
		}

		// Changing secretTemplate identity is rejected.
		badName := valid.DeepCopy()
		badName.Spec.SecretTemplate.Name = "other-sec"
		if err := k8sClient.Update(ctx, badName); err == nil || !strings.Contains(err.Error(), "secretTemplate identity fields") {
			t.Fatalf("expected secretTemplate.name immutability error, got %v", err)
		}

		// Removing secretTemplate is rejected.
		dropTpl := valid.DeepCopy()
		dropTpl.Spec.SecretTemplate = nil
		if err := k8sClient.Update(ctx, dropTpl); err == nil || !strings.Contains(err.Error(), "secretTemplate cannot be added or removed") {
			t.Fatalf("expected removing secretTemplate rejected, got %v", err)
		}

		// Changing clusterRef is rejected.
		badRef := valid.DeepCopy()
		badRef.Spec.ClusterRef.Name = "c2"
		if err := k8sClient.Update(ctx, badRef); err == nil || !strings.Contains(err.Error(), "clusterRef is immutable") {
			t.Fatalf("expected clusterRef immutability error, got %v", err)
		}
	})

	t.Run("GarageNode", func(t *testing.T) {
		cap1 := resource.MustParse("10Gi")
		cap2 := resource.MustParse("20Gi")
		node := &GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "cel-node", Namespace: ns},
			Spec: GarageNodeSpec{
				ClusterRef: ClusterReference{Name: "c1"},
				Zone:       "zone-a",
				Capacity:   &cap1,
				NodeID:     nodeID1,
			},
		}
		if err := k8sClient.Create(ctx, node); err != nil {
			t.Fatalf("create GarageNode: %v", err)
		}

		valid := node.DeepCopy()
		valid.Spec.Capacity = &cap2
		if err := k8sClient.Update(ctx, valid); err != nil {
			t.Fatalf("expected capacity update allowed: %v", err)
		}

		badNodeID := valid.DeepCopy()
		badNodeID.Spec.NodeID = nodeID2
		if err := k8sClient.Update(ctx, badNodeID); err == nil || !strings.Contains(err.Error(), "nodeId is immutable") {
			t.Fatalf("expected nodeId immutability error, got %v", err)
		}

		badBacking := valid.DeepCopy()
		badBacking.Spec.Backing = NodeBackingNodeLocalPool
		if err := k8sClient.Update(ctx, badBacking); err == nil || !strings.Contains(err.Error(), "backing is immutable") {
			t.Fatalf("expected backing immutability error, got %v", err)
		}

		badGW := valid.DeepCopy()
		badGW.Spec.Gateway = true
		if err := k8sClient.Update(ctx, badGW); err == nil || !strings.Contains(err.Error(), "gateway is immutable") {
			t.Fatalf("expected gateway immutability error, got %v", err)
		}

		badExt := valid.DeepCopy()
		badExt.Spec.External = &ExternalNodeConfig{Address: "10.0.0.5", Port: 3901}
		if err := k8sClient.Update(ctx, badExt); err == nil || !strings.Contains(err.Error(), "external versus operator-managed") {
			t.Fatalf("expected external ownership immutability error, got %v", err)
		}

		nlp := &GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "cel-node-nlp", Namespace: ns},
			Spec: GarageNodeSpec{
				ClusterRef:         ClusterReference{Name: "c1"},
				Backing:            NodeBackingNodeLocalPool,
				Zone:               "zone-a",
				Capacity:           &cap1,
				KubernetesNodeName: "worker-1",
				NodeLocalPoolName:  "nvme",
			},
		}
		if err := k8sClient.Create(ctx, nlp); err != nil {
			t.Fatalf("create NodeLocalPool GarageNode: %v", err)
		}
		badKubeNode := nlp.DeepCopy()
		badKubeNode.Spec.KubernetesNodeName = "worker-2"
		if err := k8sClient.Update(ctx, badKubeNode); err == nil || !strings.Contains(err.Error(), "kubernetesNodeName and nodeLocalPoolName are immutable") {
			t.Fatalf("expected kubernetesNodeName immutability error, got %v", err)
		}
	})

	t.Run("GarageCluster_v1beta2", func(t *testing.T) {
		size := resource.MustParse("10Gi")
		cluster := &v1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "cel-cluster", Namespace: ns},
			Spec: v1beta2.GarageClusterSpec{
				Zone:         "zone-a",
				LayoutPolicy: "Auto",
				Storage: &v1beta2.StorageSpec{
					Replicas: 3,
					Metadata: &v1beta2.VolumeConfig{Size: &size},
					Data:     &v1beta2.VolumeConfig{Size: &size},
					NodeLocalPools: []v1beta2.NodeLocalPoolSpec{
						{
							Name:     "pool-a",
							Capacity: &size,
							Metadata: &v1beta2.HostPathVolumeConfig{HostPath: "/var/lib/garage/pool-a/meta"},
							Data:     &v1beta2.HostPathVolumeConfig{HostPath: "/var/lib/garage/pool-a/data"},
						},
					},
				},
			},
		}
		if err := k8sClient.Create(ctx, cluster); err != nil {
			t.Fatalf("create storage GarageCluster: %v", err)
		}

		// Adding gateway to a storage cluster and transitioning Auto -> Manual are allowed.
		toManual := cluster.DeepCopy()
		toManual.Spec.LayoutPolicy = "Manual"
		toManual.Spec.Gateway = &v1beta2.GatewaySpec{Replicas: 1}
		if err := k8sClient.Update(ctx, toManual); err != nil {
			t.Fatalf("expected Auto->Manual and adding gateway on storage cluster allowed: %v", err)
		}

		// Transitioning Manual -> Auto must be rejected.
		backToAuto := toManual.DeepCopy()
		backToAuto.Spec.LayoutPolicy = "Auto"
		if err := k8sClient.Update(ctx, backToAuto); err == nil || !strings.Contains(err.Error(), "Manual to Auto") {
			t.Fatalf("expected Manual->Auto rejected, got %v", err)
		}

		// Changing retained nodeLocalPool metadata.hostPath must be rejected.
		badPoolPath := toManual.DeepCopy()
		badPoolPath.Spec.Storage.NodeLocalPools[0].Metadata.HostPath = "/var/lib/garage/other/meta"
		if err := k8sClient.Update(ctx, badPoolPath); err == nil || !strings.Contains(err.Error(), "nodeLocalPools[].metadata.hostPath is immutable") {
			t.Fatalf("expected nodeLocalPool hostPath immutability error, got %v", err)
		}

		// Removing storage must be rejected.
		dropStorage := toManual.DeepCopy()
		dropStorage.Spec.Storage = nil
		dropStorage.Spec.ConnectTo = &v1beta2.ConnectToConfig{AdminAPIEndpoint: "http://remote:3903"}
		if err := k8sClient.Update(ctx, dropStorage); err == nil || !strings.Contains(err.Error(), "spec.storage presence") {
			t.Fatalf("expected dropping spec.storage rejected, got %v", err)
		}

		// Management handle cannot switch to edge gateway.
		handle := &v1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "cel-handle", Namespace: ns},
			Spec: v1beta2.GarageClusterSpec{
				ConnectTo: &v1beta2.ConnectToConfig{AdminAPIEndpoint: "http://remote:3903"},
			},
		}
		if err := k8sClient.Create(ctx, handle); err != nil {
			t.Fatalf("create management handle: %v", err)
		}
		toEdge := handle.DeepCopy()
		toEdge.Spec.Gateway = &v1beta2.GatewaySpec{Replicas: 1}
		if err := k8sClient.Update(ctx, toEdge); err == nil || !strings.Contains(err.Error(), "edge-gateway versus management-handle") {
			t.Fatalf("expected handle->edge switch rejected, got %v", err)
		}
	})
}
