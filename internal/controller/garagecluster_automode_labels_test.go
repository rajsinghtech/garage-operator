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

package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

type autoModeLabelRecordingClient struct {
	client.Client
	patches int
	updates int
	deletes int
}

func (c *autoModeLabelRecordingClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	c.patches++
	return c.Client.Patch(ctx, obj, patch, opts...)
}

func (c *autoModeLabelRecordingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.updates++
	return c.Client.Update(ctx, obj, opts...)
}

func (c *autoModeLabelRecordingClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	c.deletes++
	return c.Client.Delete(ctx, obj, opts...)
}

func autoModeLabelTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := appsv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func autoModeLabelTestFixture(t *testing.T, tier string, clusterName, nodeName string) (*garagev1beta2.GarageCluster, *garagev1beta1.GarageNode, *runtime.Scheme) {
	t.Helper()
	s := autoModeLabelTestScheme(t)
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:            clusterName,
			Namespace:       "labels-ns",
			UID:             types.UID(clusterName + "-uid"),
			ResourceVersion: "1",
		},
		Spec: garagev1beta2.GarageClusterSpec{
			LayoutPolicy: LayoutPolicyAuto,
			Zone:         "test-zone",
			Storage: &garagev1beta2.StorageSpec{
				Replicas: 1,
				Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
				Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
			},
			Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
		},
	}
	if tier == tierGateway {
		cluster.Spec.Gateway = &garagev1beta2.GatewaySpec{Replicas: 1}
	}

	capacity := resource.MustParse("10Gi")
	metadataSize := resource.MustParse("1Gi")
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:            nodeName,
			Namespace:       cluster.Namespace,
			UID:             types.UID(nodeName + "-uid"),
			ResourceVersion: "2",
			Annotations:     map[string]string{"example.com/keep": "annotation"},
			Finalizers:      []string{"example.com/keep-finalizer"},
			Labels: map[string]string{
				labelCluster:       cluster.Name,
				labelTier:          tier,
				labelAppManagedBy:  managedByOperatorValue,
				labelAutoNodeSlot:  nodeName,
				"example.com/keep": "label",
			},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
				cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster),
			)},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
			Zone:       "test-zone",
			Capacity:   &capacity,
			Storage: &garagev1beta1.NodeStorageConfig{
				Metadata: &garagev1beta1.NodeVolumeConfig{Size: &metadataSize},
				Data:     &garagev1beta1.NodeVolumeConfig{Size: &capacity},
			},
		},
		Status: garagev1beta1.GarageNodeStatus{
			NodeID:             "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			ObservedPodUID:     "pod-uid-before-label-repair",
			ObservedGeneration: 7,
			Connected:          true,
			InLayout:           true,
		},
	}
	if tier == tierGateway {
		node.Spec.Gateway = true
		node.Spec.Capacity = nil
		node.Spec.Storage.Data = nil
	}
	return cluster, node, s
}

func TestAutoModeReconcileRepairsEveryGeneratedLabelInPlace(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		tier string
	}{
		{name: "storage", tier: tierStorage},
		{name: "gateway", tier: tierGateway},
	} {
		for _, labelKey := range []string{labelCluster, labelTier, labelAppManagedBy, labelAutoNodeSlot} {
			t.Run(fmt.Sprintf("%s/missing-%s", tc.name, strings.ReplaceAll(labelKey, "/", "_")), func(t *testing.T) {
				g := gomega.NewWithT(t)
				clusterName := "auto-label-" + tc.name
				nodeName := clusterName + "-" + tc.tier + "-0"
				cluster, node, s := autoModeLabelTestFixture(t, tc.tier, clusterName, nodeName)
				delete(node.Labels, labelKey)

				beforeSpec := node.Spec.DeepCopy()
				beforeStatus := node.Status.DeepCopy()
				beforeAnnotations := mapsClone(node.Annotations)
				beforeFinalizers := append([]string(nil), node.Finalizers...)
				beforeOwners := append([]metav1.OwnerReference(nil), node.OwnerReferences...)
				beforeUID := node.UID
				base := fake.NewClientBuilder().WithScheme(s).WithObjects(cluster, node).Build()
				recording := &autoModeLabelRecordingClient{Client: base}
				reconciler := &GarageClusterReconciler{Client: recording, APIReader: base, Scheme: s}

				var err error
				if tc.tier == tierGateway {
					err = reconciler.reconcileAutoModeGatewayNodes(ctx, cluster)
				} else {
					err = reconciler.reconcileAutoModeStorageNodes(ctx, cluster)
				}
				g.Expect(err).NotTo(gomega.HaveOccurred())
				g.Expect(recording.patches).To(gomega.Equal(1), "label convergence must use one metadata PATCH")
				g.Expect(recording.updates).To(gomega.Equal(0))
				g.Expect(recording.deletes).To(gomega.Equal(0))

				got := &garagev1beta1.GarageNode{}
				g.Expect(base.Get(ctx, client.ObjectKeyFromObject(node), got)).To(gomega.Succeed())
				expectedLabels := expectedAutoModeNodeLabels(cluster, tc.tier, nodeName)
				expectedLabels["example.com/keep"] = "label"
				g.Expect(got.Labels).To(gomega.Equal(expectedLabels))
				g.Expect(got.Labels).To(gomega.HaveKeyWithValue("example.com/keep", "label"))
				g.Expect(got.Annotations).To(gomega.Equal(beforeAnnotations))
				g.Expect(got.Finalizers).To(gomega.Equal(beforeFinalizers))
				g.Expect(got.OwnerReferences).To(gomega.Equal(beforeOwners))
				g.Expect(got.UID).To(gomega.Equal(beforeUID))
				g.Expect(got.Spec).To(gomega.Equal(*beforeSpec))
				g.Expect(got.Status).To(gomega.Equal(*beforeStatus))

				statefulSets := &appsv1.StatefulSetList{}
				g.Expect(base.List(ctx, statefulSets, client.InNamespace(cluster.Namespace))).To(gomega.Succeed())
				g.Expect(statefulSets.Items).To(gomega.BeEmpty())
				pods := &corev1.PodList{}
				g.Expect(base.List(ctx, pods, client.InNamespace(cluster.Namespace))).To(gomega.Succeed())
				g.Expect(pods.Items).To(gomega.BeEmpty())
			})
		}
	}
}

func TestAutoModeReconcileRepairsParseablePromotedName(t *testing.T) {
	g := gomega.NewWithT(t)
	ctx := context.Background()
	clusterName := "auto-label-cycle"
	canonicalName := clusterName + "-storage-0"
	cluster, node, s := autoModeLabelTestFixture(t, tierStorage, clusterName, canonicalName+cycleSiblingSuffix)
	delete(node.Labels, labelAutoNodeSlot)

	base := fake.NewClientBuilder().WithScheme(s).WithObjects(cluster, node).Build()
	reconciler := &GarageClusterReconciler{Client: base, APIReader: base, Scheme: s}
	g.Expect(reconciler.reconcileAutoModeStorageNodes(ctx, cluster)).To(gomega.Succeed())

	got := &garagev1beta1.GarageNode{}
	g.Expect(base.Get(ctx, client.ObjectKeyFromObject(node), got)).To(gomega.Succeed())
	g.Expect(got.Labels).To(gomega.HaveKeyWithValue(labelAutoNodeSlot, canonicalName))
	g.Expect(got.Labels).To(gomega.HaveKeyWithValue(labelCluster, clusterName))
	g.Expect(got.Labels).To(gomega.HaveKeyWithValue(labelTier, tierStorage))
	g.Expect(got.Labels).To(gomega.HaveKeyWithValue(labelAppManagedBy, managedByOperatorValue))
}

func TestAutoModeReconcileFailsClosedForBoundedPromotedNameWithoutSlot(t *testing.T) {
	g := gomega.NewWithT(t)
	ctx := context.Background()
	clusterName := strings.Repeat("a", 50)
	canonicalName := clusterName + "-storage-0"
	promotedName := boundedGarageNodeName(canonicalName + cycleSiblingSuffix)
	cluster, node, s := autoModeLabelTestFixture(t, tierStorage, clusterName, promotedName)
	delete(node.Labels, labelAutoNodeSlot)

	base := fake.NewClientBuilder().WithScheme(s).WithObjects(cluster, node).Build()
	reconciler := &GarageClusterReconciler{Client: base, APIReader: base, Scheme: s}
	err := reconciler.reconcileAutoModeStorageNodes(ctx, cluster)
	g.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("refusing to guess a bounded cycle identity")))

	got := &garagev1beta1.GarageNode{}
	g.Expect(base.Get(ctx, client.ObjectKeyFromObject(node), got)).To(gomega.Succeed())
	g.Expect(got.Labels).NotTo(gomega.HaveKey(labelAutoNodeSlot))
	g.Expect(got.UID).To(gomega.Equal(node.UID))
	nodes := &garagev1beta1.GarageNodeList{}
	g.Expect(base.List(ctx, nodes, client.InNamespace(cluster.Namespace))).To(gomega.Succeed())
	g.Expect(nodes.Items).To(gomega.HaveLen(1))
}

func TestAutoModeReconcileRepairsBoundedPromotedNameWithPersistedSlot(t *testing.T) {
	g := gomega.NewWithT(t)
	ctx := context.Background()
	clusterName := strings.Repeat("b", 50)
	canonicalName := clusterName + "-storage-0"
	promotedName := boundedGarageNodeName(canonicalName + cycleSiblingSuffix)
	cluster, node, s := autoModeLabelTestFixture(t, tierStorage, clusterName, promotedName)
	node.Labels[labelAutoNodeSlot] = canonicalName
	delete(node.Labels, labelCluster)
	delete(node.Labels, labelTier)
	delete(node.Labels, labelAppManagedBy)

	base := fake.NewClientBuilder().WithScheme(s).WithObjects(cluster, node).Build()
	reconciler := &GarageClusterReconciler{Client: base, APIReader: base, Scheme: s}
	g.Expect(reconciler.reconcileAutoModeStorageNodes(ctx, cluster)).To(gomega.Succeed())

	got := &garagev1beta1.GarageNode{}
	g.Expect(base.Get(ctx, client.ObjectKeyFromObject(node), got)).To(gomega.Succeed())
	expectedLabels := expectedAutoModeNodeLabels(cluster, tierStorage, canonicalName)
	expectedLabels["example.com/keep"] = "label"
	g.Expect(got.Labels).To(gomega.Equal(expectedLabels))
}

func TestAutoModeReconcileRejectsUnownedCanonicalCollision(t *testing.T) {
	for _, tc := range []struct {
		name       string
		foreignUID types.UID
	}{
		{name: "ownerless"},
		{name: "foreign-owner", foreignUID: "different-cluster-uid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			ctx := context.Background()
			clusterName := "auto-label-collision-" + tc.name
			canonicalName := clusterName + "-storage-0"
			cluster, node, s := autoModeLabelTestFixture(t, tierStorage, clusterName, canonicalName)
			if tc.foreignUID == "" {
				node.OwnerReferences = nil
			} else {
				foreign := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
					Name: "foreign", Namespace: cluster.Namespace, UID: tc.foreignUID,
				}}
				node.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(
					foreign, garagev1beta2.GroupVersion.WithKind(kindGarageCluster),
				)}
			}
			beforeLabels := mapsClone(node.Labels)
			base := fake.NewClientBuilder().WithScheme(s).WithObjects(cluster, node).Build()
			recording := &autoModeLabelRecordingClient{Client: base}
			reconciler := &GarageClusterReconciler{Client: recording, APIReader: base, Scheme: s}

			err := reconciler.reconcileAutoModeStorageNodes(ctx, cluster)
			g.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("occupied without the exact GarageCluster controller UID")))
			g.Expect(recording.patches).To(gomega.Equal(0))
			g.Expect(recording.updates).To(gomega.Equal(0))
			g.Expect(recording.deletes).To(gomega.Equal(0))

			got := &garagev1beta1.GarageNode{}
			g.Expect(base.Get(ctx, client.ObjectKeyFromObject(node), got)).To(gomega.Succeed())
			g.Expect(got.Labels).To(gomega.Equal(beforeLabels))
		})
	}
}

func mapsClone(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
