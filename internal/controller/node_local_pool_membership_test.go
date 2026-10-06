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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	membershipTestNamespace     = "garage-system"
	membershipTestDiskLabel     = "membership.example/disk"
	membershipTestFastPool      = "speedy"
	membershipTestArchivePool   = "cold"
	membershipTestSelectedLabel = "membership.example/selected"
	membershipTestSelectedValue = "yes"
	membershipTestWorkerName    = "membership-worker"
)

type nodeListCountingReader struct {
	client.Reader
	nodeLists int
}

func (r *nodeListCountingReader) List(
	ctx context.Context,
	list client.ObjectList,
	opts ...client.ListOption,
) error {
	if _, ok := list.(*corev1.NodeList); ok {
		r.nodeLists++
	}
	return r.Reader.List(ctx, list, opts...)
}

func TestNodeLocalPoolMembershipUsesOneNodeList(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	nodes := []client.Object{
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "fast-a", Labels: map[string]string{membershipTestDiskLabel: membershipTestFastPool}}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "archive-a", Labels: map[string]string{membershipTestDiskLabel: membershipTestArchivePool}}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "unselected", Labels: map[string]string{membershipTestDiskLabel: "none"}}},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(nodes...).Build()
	reader := &nodeListCountingReader{Reader: kubeClient}
	reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: reader}
	cluster := &garagev1beta2.GarageCluster{Spec: garagev1beta2.GarageClusterSpec{
		Storage: &garagev1beta2.StorageSpec{NodeLocalPools: []garagev1beta2.NodeLocalPoolSpec{
			{Name: membershipTestFastPool, Selector: metav1.LabelSelector{MatchLabels: map[string]string{membershipTestDiskLabel: membershipTestFastPool}}},
			{Name: membershipTestArchivePool, Selector: metav1.LabelSelector{MatchLabels: map[string]string{membershipTestDiskLabel: membershipTestArchivePool}}},
		}},
	}}
	membership, err := reconciler.readNodeLocalPoolMembership(context.Background(), cluster)
	if err != nil {
		t.Fatal(err)
	}
	if reader.nodeLists != 1 {
		t.Fatalf("evaluating two selectors used %d Kubernetes Node LISTs", reader.nodeLists)
	}
	if membership.selectedMembers != 2 || membership.poolByNode["fast-a"] != membershipTestFastPool ||
		membership.poolByNode["archive-a"] != membershipTestArchivePool {
		t.Fatalf("unexpected membership: %#v", membership)
	}
}

func TestNodeLocalPoolMembershipBoundsAndConflicts(t *testing.T) {
	t.Parallel()
	pool := garagev1beta2.NodeLocalPoolSpec{
		Name: "all", Selector: metav1.LabelSelector{MatchLabels: map[string]string{tierStorage: testTagLocal}},
	}
	makeNodes := func(count int) []corev1.Node {
		nodes := make([]corev1.Node, count)
		for i := range nodes {
			nodes[i] = corev1.Node{ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("worker-%03d", i), Labels: map[string]string{tierStorage: testTagLocal},
			}}
		}
		return nodes
	}
	for _, count := range []int{maxNodeLocalPoolMembers, maxNodeLocalPoolMembers + 1} {
		membership, err := evaluateNodeLocalPoolMembership([]garagev1beta2.NodeLocalPoolSpec{pool}, makeNodes(count))
		if err != nil {
			t.Fatal(err)
		}
		if membership.selectedMembers != count {
			t.Fatalf("selected %d members, want %d", membership.selectedMembers, count)
		}
	}

	conflicting, err := evaluateNodeLocalPoolMembership([]garagev1beta2.NodeLocalPoolSpec{
		{Name: "a", Selector: metav1.LabelSelector{MatchLabels: map[string]string{tierStorage: testTagLocal}}},
		{Name: "b", Selector: metav1.LabelSelector{MatchLabels: map[string]string{tierStorage: testTagLocal}}},
	}, makeNodes(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicting.selectorConflicts) != 1 || conflicting.selectorConflicts[0] != "worker-000=a/b" {
		t.Fatalf("unexpected deterministic selector conflict: %#v", conflicting.selectorConflicts)
	}
}

func TestNodeLocalPoolMemberLimitFailsBeforeActivation(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "too-many-local-members", Namespace: membershipTestNamespace,
			UID: types.UID("cluster-uid"), Generation: 2,
		},
		Spec: garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{
			NodeLocalPools: []garagev1beta2.NodeLocalPoolSpec{{
				Name: testTagLocal, Selector: metav1.LabelSelector{MatchLabels: map[string]string{tierStorage: testTagLocal}},
			}},
		}},
	}
	objects := make([]client.Object, 0, maxNodeLocalPoolMembers+2)
	objects = append(objects, cluster)
	for i := 0; i <= maxNodeLocalPoolMembers; i++ {
		objects = append(objects, &corev1.Node{ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("worker-%03d", i), Labels: map[string]string{tierStorage: testTagLocal},
		}})
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		WithObjects(objects...).Build()
	reconciler := &GarageClusterReconciler{
		Client: kubeClient, APIReader: kubeClient, ClusterScoped: true,
		NodeLocalPoolPrerequisites: supportedNodeLocalPoolPrerequisites(),
	}
	if err := reconciler.reconcileNodeLocalPools(
		context.Background(), cluster, map[string]string{testTagLocal: "config-hash"},
	); err != nil {
		t.Fatal(err)
	}
	daemonSets := &appsv1.DaemonSetList{}
	if err := kubeClient.List(context.Background(), daemonSets, client.InNamespace(cluster.Namespace)); err != nil {
		t.Fatal(err)
	}
	if len(daemonSets.Items) != 0 {
		t.Fatalf("member-limit refusal created %d DaemonSet(s)", len(daemonSets.Items))
	}
	freshCluster := &garagev1beta2.GarageCluster{}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), freshCluster); err != nil {
		t.Fatal(err)
	}
	condition := findNodeLocalPoolsReadyCondition(freshCluster)
	if condition == nil || condition.Reason != garagev1beta1.ReasonNodeLocalPoolMemberLimitExceeded {
		t.Fatalf("member-limit condition missing: %#v", condition)
	}
	freshNodes := &corev1.NodeList{}
	if err := kubeClient.List(context.Background(), freshNodes); err != nil {
		t.Fatal(err)
	}
	for i := range freshNodes.Items {
		if len(freshNodes.Items[i].Annotations) != 0 || len(freshNodes.Items[i].Labels) != 1 {
			t.Fatalf("member-limit refusal activated Node %s: %#v", freshNodes.Items[i].Name, freshNodes.Items[i].ObjectMeta)
		}
	}
}

func TestNodeLocalPoolConditionSummaryIsBounded(t *testing.T) {
	t.Parallel()
	items := make([]string, maxNodeLocalPoolMembers)
	for i := range items {
		items[i] = fmt.Sprintf("pool/%s-%03d", strings.Repeat("n", 240), i)
	}
	message := summarizeNodeLocalPoolItems("waiting for node-local members", items)
	if len(message) > statusConditionMessageLimit || len(message) >= 32768 {
		t.Fatalf("condition summary is too large: %d bytes", len(message))
	}
	if !strings.Contains(message, "255 total") || !strings.Contains(message, "250 more") {
		t.Fatalf("condition summary lost cardinality: %q", message)
	}
	bounded := limitStatusConditionMessage(strings.Repeat("界", statusConditionMessageLimit))
	if len(bounded) > statusConditionMessageLimit || !utf8.ValidString(bounded) || !strings.HasSuffix(bounded, "...") {
		t.Fatalf("generic condition bound is invalid: bytes=%d validUTF8=%v suffix=%q", len(bounded), utf8.ValidString(bounded), bounded[len(bounded)-3:])
	}
}

func TestStorageSafetyConditionSettersBoundUTF8Messages(t *testing.T) {
	t.Parallel()
	longMessage := strings.Repeat("界", statusConditionMessageLimit)
	assertBounded := func(name string, condition *metav1.Condition) {
		t.Helper()
		if condition == nil {
			t.Fatalf("%s condition was not published", name)
		}
		if len(condition.Message) > statusConditionMessageLimit ||
			!utf8.ValidString(condition.Message) || !strings.HasSuffix(condition.Message, "...") {
			t.Fatalf("%s condition was not safely bounded: bytes=%d validUTF8=%v", name,
				len(condition.Message), utf8.ValidString(condition.Message))
		}
	}

	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
		Name: "bounded-storage-conditions", Namespace: membershipTestNamespace,
		UID: types.UID("bounded-storage-conditions-uid"), Generation: 7,
	}}
	setStorageDrainCondition(cluster, metav1.ConditionFalse, garagev1beta1.ReasonStorageDraining, longMessage)
	assertBounded("StorageDrainReady", meta.FindStatusCondition(
		cluster.Status.Conditions, garagev1beta1.ConditionStorageDrainReady,
	))

	scheme := runtime.NewScheme()
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		WithObjects(cluster).Build()
	reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient}
	if err := reconciler.setStorageRolloutCondition(
		context.Background(), cluster, metav1.ConditionFalse,
		garagev1beta1.ReasonStorageRollingOut, longMessage,
	); err != nil {
		t.Fatal(err)
	}
	fresh := &garagev1beta2.GarageCluster{}
	if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(cluster), fresh); err != nil {
		t.Fatal(err)
	}
	assertBounded("StorageRolloutReady", meta.FindStatusCondition(
		fresh.Status.Conditions, garagev1beta1.ConditionStorageRolloutReady,
	))
}

func TestGarageStorageRoleCapacityBoundary(t *testing.T) {
	t.Parallel()
	capacity := uint64(1)
	makeLayout := func(count int) *garage.ClusterLayout {
		layout := &garage.ClusterLayout{Roles: make([]garage.LayoutNodeRole, count)}
		for i := range layout.Roles {
			layout.Roles[i] = garage.LayoutNodeRole{
				ID: fmt.Sprintf("%064x", i+1), Capacity: &capacity,
			}
		}
		return layout
	}
	addition := garage.NodeRoleChange{ID: fmt.Sprintf("%064x", 999), Capacity: &capacity, Tags: []string{}}
	if err := requireGarageStorageRoleCapacity(makeLayout(255), []garage.NodeRoleChange{addition}); err != nil {
		t.Fatalf("Garage's legal 256th hard-limit role was rejected: %v", err)
	}
	if err := requireGarageStorageRoleCapacity(makeLayout(256), []garage.NodeRoleChange{addition}); err == nil {
		t.Fatal("a projected 257th storage role was accepted")
	}
	removal := garage.NodeRoleChange{ID: fmt.Sprintf("%064x", 1), Remove: true}
	if err := requireGarageStorageRoleCapacity(makeLayout(256), []garage.NodeRoleChange{removal}); err != nil {
		t.Fatalf("draining from the hard limit was blocked: %v", err)
	}
	if err := requireGarageStorageRoleCapacity(makeLayout(257), nil); err == nil {
		t.Fatal("an already oversized layout was treated as safe")
	}
}

func TestNodeLocalPoolActivationUsesOnlyTransientRoleReserve(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	capacityQuantity := resource.MustParse("100Gi")
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "headroom", Namespace: membershipTestNamespace, UID: types.UID("headroom-uid")},
		Spec: garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{
			Replicas: 0,
			NodeLocalPools: []garagev1beta2.NodeLocalPoolSpec{{
				Name: testTagLocal, Selector: metav1.LabelSelector{MatchLabels: map[string]string{membershipTestSelectedLabel: membershipTestSelectedValue}},
				Capacity: &capacityQuantity,
			}},
		}},
	}
	candidate := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: "candidate", Labels: map[string]string{membershipTestSelectedLabel: membershipTestSelectedValue},
	}}
	baseObjects := []client.Object{cluster, candidate}
	capacity := uint64(1)
	makeLayout := func(count int) *garage.ClusterLayout {
		layout := &garage.ClusterLayout{Roles: make([]garage.LayoutNodeRole, count)}
		for i := range layout.Roles {
			layout.Roles[i] = garage.LayoutNodeRole{ID: fmt.Sprintf("%064x", i+1), Capacity: &capacity}
		}
		return layout
	}

	t.Run("255th steady role is accepted", func(t *testing.T) {
		kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(baseObjects...).Build()
		reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient,
			nodeLocalPoolLayoutGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.ClusterLayout, error) {
				return makeLayout(254), nil
			},
		}
		if err := reconciler.requireNodeLocalPoolActivationHeadroom(
			context.Background(), cluster, testTagLocal, candidate.Name,
		); err != nil {
			t.Fatalf("255th steady role rejected: %v", err)
		}
	})

	t.Run("final hard-limit slot is rejected for steady growth", func(t *testing.T) {
		kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(baseObjects...).Build()
		reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient,
			nodeLocalPoolLayoutGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.ClusterLayout, error) {
				return makeLayout(255), nil
			},
		}
		err := reconciler.requireNodeLocalPoolActivationHeadroom(
			context.Background(), cluster, testTagLocal, candidate.Name,
		)
		if !errors.Is(err, errNodeLocalPoolGarageRoleLimit) || !strings.Contains(err.Error(), "no locally proven retiring") {
			t.Fatalf("steady 256th role was not rejected precisely: %v", err)
		}
	})

	t.Run("staged additions consume node-local headroom", func(t *testing.T) {
		kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(baseObjects...).Build()
		reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient,
			nodeLocalPoolLayoutGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.ClusterLayout, error) {
				layout := makeLayout(254)
				layout.StagedRoleChanges = []garage.NodeRoleChange{{
					ID: fmt.Sprintf("%064x", 900), Capacity: &capacity, Tags: []string{},
				}}
				return layout, nil
			},
		}
		err := reconciler.requireNodeLocalPoolActivationHeadroom(
			context.Background(), cluster, testTagLocal, candidate.Name,
		)
		if !errors.Is(err, errNodeLocalPoolGarageRoleLimit) || !strings.Contains(err.Error(), "no locally proven retiring") {
			t.Fatalf("staged 255th role did not consume node-local headroom: %v", err)
		}
	})

	t.Run("staged removals do not restore headroom before commit", func(t *testing.T) {
		kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(baseObjects...).Build()
		reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient,
			nodeLocalPoolLayoutGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.ClusterLayout, error) {
				layout := makeLayout(255)
				layout.StagedRoleChanges = []garage.NodeRoleChange{{ID: fmt.Sprintf("%064x", 1), Remove: true}}
				return layout, nil
			},
		}
		err := reconciler.requireNodeLocalPoolActivationHeadroom(
			context.Background(), cluster, testTagLocal, candidate.Name,
		)
		if !errors.Is(err, errNodeLocalPoolGarageRoleLimit) || !strings.Contains(err.Error(), "no locally proven retiring") {
			t.Fatalf("uncommitted staged removal restored headroom: %v", err)
		}
	})

	t.Run("temporarily empty declared pool does not supply a retirement slot", func(t *testing.T) {
		emptyPoolCluster := cluster.DeepCopy()
		emptyPoolCluster.Spec.Storage.NodeLocalPools = []garagev1beta2.NodeLocalPoolSpec{
			{
				Name: membershipTestArchivePool,
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{
					membershipTestDiskLabel: membershipTestArchivePool,
				}},
			},
			cluster.Spec.Storage.NodeLocalPools[0],
		}
		retained := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: "empty-pool-member", Namespace: cluster.Namespace,
				Labels: map[string]string{
					labelCluster: cluster.Name, labelTier: tierStorage,
					labelAppManagedBy: managedByOperatorValue, labelNodeLocalPool: membershipTestArchivePool,
				},
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
					emptyPoolCluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster),
				)},
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef:         garagev1beta1.ClusterReference{Name: cluster.Name},
				Backing:            garagev1beta1.NodeBackingNodeLocalPool,
				NodeLocalPoolName:  membershipTestArchivePool,
				KubernetesNodeName: "empty-pool-node",
			},
			Status: garagev1beta1.GarageNodeStatus{NodeID: fmt.Sprintf("%064x", 1)},
		}
		kubeClient := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(emptyPoolCluster, candidate, retained).Build()
		reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient,
			nodeLocalPoolLayoutGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.ClusterLayout, error) {
				return makeLayout(255), nil
			},
		}
		err := reconciler.requireNodeLocalPoolActivationHeadroom(
			context.Background(), emptyPoolCluster, testTagLocal, candidate.Name,
		)
		if !errors.Is(err, errNodeLocalPoolGarageRoleLimit) || !strings.Contains(err.Error(), "no locally proven retiring") {
			t.Fatalf("temporarily empty declared pool supplied false retirement headroom: %v", err)
		}
	})

	t.Run("locally proven replacement may use the final slot", func(t *testing.T) {
		stale := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: "stale", Namespace: cluster.Namespace,
				Labels: map[string]string{
					labelCluster: cluster.Name, labelTier: tierStorage,
					labelAppManagedBy: managedByOperatorValue, labelNodeLocalPool: testTagLocal,
				},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: garagev1beta2.GroupVersion.String(), Kind: kindGarageCluster,
					Name: cluster.Name, UID: cluster.UID, Controller: ptr.To(true),
				}},
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef:        garagev1beta1.ClusterReference{Name: cluster.Name},
				Backing:           garagev1beta1.NodeBackingNodeLocalPool,
				NodeLocalPoolName: testTagLocal, KubernetesNodeName: "retiring",
			},
			Status: garagev1beta1.GarageNodeStatus{NodeID: fmt.Sprintf("%064x", 1)},
		}
		retiringNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "retiring"}}
		objects := append(append([]client.Object(nil), baseObjects...), stale, retiringNode)
		kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
		reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient,
			nodeLocalPoolLayoutGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.ClusterLayout, error) {
				return makeLayout(255), nil
			},
		}
		if err := reconciler.requireNodeLocalPoolActivationHeadroom(
			context.Background(), cluster, testTagLocal, candidate.Name,
		); err != nil {
			t.Fatalf("transient replacement slot rejected: %v", err)
		}
	})

	t.Run("Garage hard maximum rejects another activation", func(t *testing.T) {
		kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(baseObjects...).Build()
		reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient,
			nodeLocalPoolLayoutGetter: func(context.Context, *garagev1beta2.GarageCluster) (*garage.ClusterLayout, error) {
				return makeLayout(256), nil
			},
		}
		if err := reconciler.requireNodeLocalPoolActivationHeadroom(
			context.Background(), cluster, testTagLocal, candidate.Name,
		); !errors.Is(err, errNodeLocalPoolGarageRoleLimit) {
			t.Fatalf("257th role was accepted: %v", err)
		}
	})
}

func TestClustersForKubernetesNodeFiltersNodeLocalSelectors(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	makeCluster := func(name string, selector metav1.LabelSelector) *garagev1beta2.GarageCluster {
		return &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: membershipTestNamespace},
			Spec: garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{
				NodeLocalPools: []garagev1beta2.NodeLocalPoolSpec{{Name: testTagLocal, Selector: selector}},
			}},
		}
	}
	fast := makeCluster(membershipTestFastPool, metav1.LabelSelector{MatchLabels: map[string]string{membershipTestDiskLabel: membershipTestFastPool}})
	archive := makeCluster(membershipTestArchivePool, metav1.LabelSelector{MatchLabels: map[string]string{membershipTestDiskLabel: membershipTestArchivePool}})
	withoutMaintenance := makeCluster("without-maintenance", metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: "maintenance", Operator: metav1.LabelSelectorOpDoesNotExist,
	}}})
	zoneDerived := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "zone-derived", Namespace: membershipTestNamespace},
		Spec:       garagev1beta2.GarageClusterSpec{ZoneFrom: &garagev1beta2.ZoneSource{NodeLabel: "topology.example/zone"}},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(fast, archive, withoutMaintenance, zoneDerived).Build()
	reconciler := &GarageClusterReconciler{Client: kubeClient}
	requests := reconciler.clustersForKubernetesNode(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: membershipTestWorkerName, Labels: map[string]string{membershipTestDiskLabel: membershipTestFastPool},
	}})
	got := make(map[string]bool, len(requests))
	for i := range requests {
		got[requests[i].Name] = true
	}
	if !got[membershipTestFastPool] || !got["without-maintenance"] || !got["zone-derived"] || got[membershipTestArchivePool] {
		t.Fatalf("unexpected filtered requests: %#v", got)
	}

	// controller-runtime invokes the map function on both objects in an Update,
	// so the old object preserves the removal edge and the new object discovers
	// the addition edge.
	oldRequests := reconciler.clustersForKubernetesNode(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: membershipTestWorkerName, Labels: map[string]string{membershipTestDiskLabel: membershipTestFastPool},
	}})
	newRequests := reconciler.clustersForKubernetesNode(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: membershipTestWorkerName, Labels: map[string]string{membershipTestDiskLabel: membershipTestArchivePool, "maintenance": annotationTrue},
	}})
	union := make(map[string]bool)
	for _, request := range append(oldRequests, newRequests...) {
		union[request.Name] = true
	}
	if !union[membershipTestFastPool] || !union[membershipTestArchivePool] || !union["without-maintenance"] {
		t.Fatalf("old/new selector edge was lost: %#v", union)
	}
}

func TestReportedLayoutHistoryIsBoundedWithoutHidingActiveVersions(t *testing.T) {
	t.Parallel()
	versions := make([]garage.LayoutVersion, maximumReportedLayoutHistoryVersions+12)
	for i := range versions {
		versions[i] = garage.LayoutVersion{
			Version: uint64(i + 1), Status: garage.LayoutVersionStatusHistorical,
		}
	}
	// Deliberately violate Garage v2.3's newest-first response order. The status
	// projection must still retain active versions; safety logic consumes the
	// complete unprojected response elsewhere.
	versions[len(versions)-2].Status = garage.LayoutVersionStatusDraining
	versions[len(versions)-1].Status = garage.LayoutVersionStatusCurrent

	reported := reportedLayoutHistoryVersions(versions)
	if len(reported) != maximumReportedLayoutHistoryVersions {
		t.Fatalf("reported %d layout versions, want %d", len(reported), maximumReportedLayoutHistoryVersions)
	}
	if reported[0].Status != garage.LayoutVersionStatusDraining ||
		reported[1].Status != garage.LayoutVersionStatusCurrent {
		t.Fatalf("bounded projection hid/reordered active layout versions behind history: %#v", reported[:2])
	}
	if versions[0].Status != garage.LayoutVersionStatusHistorical || len(versions) != maximumReportedLayoutHistoryVersions+12 {
		t.Fatal("status projection mutated Garage's complete safety input")
	}
}

// The deprecated status fields that the operator never writes (#474: nodes,
// activeRepairs, workers, workerCount, workersFailed, scrubStatus,
// lifecycleStatus, totalNodes) are always empty, so they are not projected.
func TestNodeLocalPoolProjectedSafetyStatusBudget(t *testing.T) {
	t.Parallel()
	const (
		maximumResyncWorkersPerNode  = 8   // API validation maximum
		maximumPositiveCapacityRoles = 256 // Garage CompactNodeType hard limit
		drainTransactionBudget       = 512 * 1024
		statusSafetyBudget           = 1024 * 1024 // leaves at least 512 KiB of the 1.5 MiB API-object envelope for spec/metadata
	)
	observedAt := metav1.NewTime(time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC))
	largeQuantity := resource.MustParse("8192Pi")
	quantity := func() *resource.Quantity {
		copy := largeQuantity.DeepCopy()
		return &copy
	}
	garageClusterConditionTypes := []string{
		garagev1beta1.ConditionReady,
		garagev1beta1.ConditionReconciling,
		garagev1beta1.ConditionDegraded,
		garagev1beta1.ConditionError,
		garagev1beta1.ConditionClusterHealthy,
		garagev1beta1.ConditionLayoutApplied,
		garagev1beta1.ConditionLayoutStaged,
		garagev1beta1.ConditionNodesConnected,
		garagev1beta1.ConditionFederationReady,
		garagev1beta1.ConditionStatefulSetReady,
		garagev1beta1.ConditionServicesReady,
		garagev1beta1.ConditionGatewayConnected,
		garagev1beta1.ConditionPublicEndpointReady,
		garagev1beta1.ConditionGatewayTombstones,
		garagev1beta1.ConditionLegacySTSMigrated,
		garagev1beta1.ConditionQuorumAtRisk,
		garagev1beta1.ConditionRemoteClustersHealthy,
		garagev1beta1.ConditionFederationConfigured,
		garagev1beta1.ConditionPeerUnreachable,
		garagev1beta1.ConditionGatewayLayoutDegraded,
		garagev1beta1.ConditionManagementHandleReady,
		garagev1beta1.ConditionStorageScaleDownBlocked,
		garagev1beta1.ConditionStorageTopologyReady,
		garagev1beta1.ConditionNodeLocalPoolsReady,
		garagev1beta1.ConditionStorageRolloutReady,
		garagev1beta1.ConditionStorageDrainReady,
		garagev1beta1.ConditionOperatorAdminTokenReady,
		garagev1beta1.ConditionFullyReplicated,
	}
	drain := &garagev1beta2.StorageDrainStatus{
		Actor: garagev1beta2.StorageDrainActorStatus{
			APIVersion: garagev1beta2.GroupVersion.String(), Kind: kindGarageCluster,
			Namespace: strings.Repeat("n", 63), Name: strings.Repeat("c", 253), UID: strings.Repeat("u", 36),
		},
		TransactionID:            strings.Repeat("t", 64),
		TargetHash:               strings.Repeat("h", 64),
		StartedAt:                observedAt,
		ManagedPodUIDs:           make(map[string]string, maximumPositiveCapacityRoles),
		RepairBaselines:          make(map[string]uint64, maximumPositiveCapacityRoles),
		RepairWorkerIDs:          make(map[string]uint64, maximumPositiveCapacityRoles),
		ResyncErrorBaselines:     make(map[string]uint64, maximumPositiveCapacityRoles*maximumResyncWorkersPerNode),
		RoleRemovalNodeIDs:       make([]string, 0, maximumPositiveCapacityRoles),
		RemovedStorageNodeIDs:    make([]string, 0, maximumPositiveCapacityRoles),
		UnavailableSourceNodeIDs: make([]string, 0, maximumPositiveCapacityRoles),
		VerificationNodeIDs:      make([]string, 0, maximumPositiveCapacityRoles),
		LayoutVersion:            ^uint64(0),
		QueueLength:              ^uint64(0),
		ErrorCount:               ^uint64(0),
		RequiresEmptyQueue:       true,
		QuietSince:               &observedAt,
		CompletedAt:              &observedAt,
	}
	status := garagev1beta2.GarageClusterStatus{
		Phase: "Deleting", Replicas: maximumPositiveCapacityRoles,
		Selector: strings.Repeat("s", 1024), ClusterID: strings.Repeat("f", 64),
		BuildInfo: &garagev1beta2.GarageBuildInfo{
			Version: strings.Repeat("v", 128), RustVersion: strings.Repeat("r", 128),
			Features: []string{strings.Repeat("f", 128)},
		},
		ReadyReplicas: maximumPositiveCapacityRoles, StorageReplicas: maximumPositiveCapacityRoles,
		StorageReadyReplicas: maximumPositiveCapacityRoles, GatewayReplicas: maximumPositiveCapacityRoles,
		GatewayReadyReplicas: maximumPositiveCapacityRoles,
		LayoutVersion:        int64(^uint64(0) >> 1), StagedRoles: maximumPositiveCapacityRoles,
		Health: &garagev1beta2.ClusterHealth{
			Status: strings.Repeat("h", 64), KnownNodes: maximumPositiveCapacityRoles,
			ConnectedNodes: maximumPositiveCapacityRoles, StorageNodes: maximumPositiveCapacityRoles,
			StorageNodesOK: maximumPositiveCapacityRoles, Partitions: 32768,
			PartitionsQuorum: 32768, PartitionsAllOK: 32768,
		},
		StorageStats: &garagev1beta2.ClusterStorageStats{
			TotalCapacity: quantity(), UsedCapacity: quantity(), AvailableCapacity: quantity(),
			TotalPartitions: 32768, HealthyPartitions: 32768,
		},
		LayoutHistory: &garagev1beta2.LayoutHistoryStatus{
			CurrentVersion: int64(^uint64(0) >> 1), MinAck: int64(^uint64(0) >> 1),
			Versions: make([]garagev1beta2.LayoutVersionInfo, 0, maximumReportedLayoutHistoryVersions),
		},
		BlockErrors: ptr.To[int32](maximumPositiveCapacityRoles),
		BlockErrorDetails: &garagev1beta2.BlockErrorsStatus{
			Count: maximumPositiveCapacityRoles, LastErrorAt: &observedAt,
			TopErrors: make([]garagev1beta2.BlockErrorDetail, 0, maximumReportedBlockErrors),
		},
		ResyncQueueLength: ptr.To(int64(^uint64(0) >> 1)), StorageDrain: drain,
		LastOperation: &garagev1beta2.LastOperationStatus{
			Type: strings.Repeat("o", 128), TriggeredAt: &observedAt, Error: strings.Repeat("e", 1024),
		},
		Endpoints: &garagev1beta2.ClusterEndpoints{
			S3: strings.Repeat("s", 253), K2V: strings.Repeat("k", 253), Web: strings.Repeat("w", 253),
			Admin: strings.Repeat("a", 253), Metrics: strings.Repeat("m", 253), RPC: strings.Repeat("r", 253),
		},
		RemoteClusters:           make([]garagev1beta2.RemoteClusterStatus, 0, maximumPositiveCapacityRoles),
		DrainingNodes:            maximumPositiveCapacityRoles,
		PendingGatewayTombstones: make([]string, 0, maximumPositiveCapacityRoles),
		LayoutDiagnosis:          strings.Repeat("l", statusConditionMessageLimit),
		UnreachablePeers:         make([]string, 0, maximumPositiveCapacityRoles),
		GatewayNodesNotInLayout:  make([]string, 0, maximumPositiveCapacityRoles),
		ObservedGeneration:       int64(^uint64(0) >> 1),
		Conditions:               make([]metav1.Condition, 0, len(garageClusterConditionTypes)),
	}
	// A redundancy proof drops its evidence while a drain runs (#474), so the
	// coexisting worst case is the verification header plus every node's
	// progress; the largest evidence is checked against the drain's budget.
	status.Redundancy = &garagev1beta2.RedundancyStatus{
		Verification: &garagev1beta2.RedundancyVerificationStatus{
			Phase: garagev1beta2.RedundancyPhaseSettling, Trigger: garagev1beta2.RedundancyTriggerLayoutChanged,
			StartedAt: &observedAt, PhaseStartedAt: &observedAt, VerifiedAt: &observedAt,
			LayoutVersion: int64(^uint64(0) >> 1), MembershipHash: strings.Repeat("m", 64),
			RequestToken: strings.Repeat("t", 253),
		},
		ProgressObservedAt: &observedAt, LastProgressAt: &observedAt,
		Nodes: make([]garagev1beta2.NodeRedundancyStatus, 0, maximumPositiveCapacityRoles),
	}
	blocksEvidence := &garagev1beta2.RedundancyProofEvidence{
		VerificationNodeIDs:   make([]string, 0, maximumPositiveCapacityRoles),
		RepairBaselines:       make(map[string]uint64, maximumPositiveCapacityRoles),
		RepairWorkerIDs:       make(map[string]uint64, maximumPositiveCapacityRoles),
		ResyncErrorBaselines:  make(map[string]uint64, maximumPositiveCapacityRoles*maximumResyncWorkersPerNode),
		QuietSince:            &observedAt,
		BlockErrorsBaseline:   ptr.To(int64(^uint64(0) >> 1)),
		BlockErrorsBaselineAt: &observedAt,
	}
	metadataEvidence := &garagev1beta2.RedundancyProofEvidence{
		MetadataLaunchedAt:      &observedAt,
		MetadataWorkerBaselines: make(map[string]uint64, maximumPositiveCapacityRoles),
		MetadataErrorBaselines:  make(map[string]uint64, maximumPositiveCapacityRoles*len(redundancyMetadataTables)),
		MetadataIdleSince:       &observedAt,
		BlockErrorsBaseline:     ptr.To(int64(^uint64(0) >> 1)),
		BlockErrorsBaselineAt:   &observedAt,
	}
	for i := 0; i < maximumPositiveCapacityRoles; i++ {
		nodeID := fmt.Sprintf("%064x", i+1)
		status.Redundancy.Nodes = append(status.Redundancy.Nodes, garagev1beta2.NodeRedundancyStatus{
			NodeID: nodeID, Observed: true, ResyncQueueLength: ptr.To(int64(^uint64(0) >> 1)), ResyncIdle: ptr.To(false),
			BlockErrors: ptr.To(int32(^uint32(0) >> 1)), MetadataSyncPartitions: ptr.To(int32(^uint32(0) >> 1)),
			MetadataQueueLength: ptr.To(int64(^uint64(0) >> 1)), BlockRepairProgress: strings.Repeat("p", 64),
		})
		blocksEvidence.VerificationNodeIDs = append(blocksEvidence.VerificationNodeIDs, nodeID)
		blocksEvidence.RepairBaselines[nodeID] = ^uint64(0)
		blocksEvidence.RepairWorkerIDs[nodeID] = ^uint64(0)
		metadataEvidence.MetadataWorkerBaselines[nodeID] = ^uint64(0)
		for worker := 0; worker < maximumResyncWorkersPerNode; worker++ {
			blocksEvidence.ResyncErrorBaselines[redundancyWorkerKey(nodeID, ^uint64(0)-uint64(worker))] = ^uint64(0)
		}
		for table := range redundancyMetadataTables {
			metadataEvidence.MetadataErrorBaselines[redundancyWorkerKey(nodeID, ^uint64(0)-uint64(table))] = ^uint64(0)
		}
	}
	for _, evidence := range []*garagev1beta2.RedundancyProofEvidence{blocksEvidence, metadataEvidence} {
		encoded, err := json.Marshal(evidence)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("projected redundancy proof evidence: %d bytes", len(encoded))
		if len(encoded) > drainTransactionBudget {
			t.Fatalf("projected redundancy proof evidence is %d bytes, above the %d-byte drain budget it replaces", len(encoded), drainTransactionBudget)
		}
	}
	for i := 0; i < maximumPositiveCapacityRoles; i++ {
		nodeID := fmt.Sprintf("%064x", i+1)
		drain.RoleRemovalNodeIDs = append(drain.RoleRemovalNodeIDs, nodeID)
		drain.RemovedStorageNodeIDs = append(drain.RemovedStorageNodeIDs, nodeID)
		drain.UnavailableSourceNodeIDs = append(drain.UnavailableSourceNodeIDs, nodeID)
		drain.VerificationNodeIDs = append(drain.VerificationNodeIDs, nodeID)
		drain.ManagedPodUIDs[nodeID] = fmt.Sprintf("%036d", i)
		drain.RepairBaselines[nodeID] = ^uint64(0)
		drain.RepairWorkerIDs[nodeID] = ^uint64(0)
		for worker := 0; worker < maximumResyncWorkersPerNode; worker++ {
			workerID := ^uint64(0) - uint64(worker)
			drain.ResyncErrorBaselines[fmt.Sprintf("%s/%d", nodeID, workerID)] = ^uint64(0)
		}
		if i < maximumReportedLayoutHistoryVersions {
			status.LayoutHistory.Versions = append(status.LayoutHistory.Versions, garagev1beta2.LayoutVersionInfo{
				Version: int64(^uint64(0) >> 1), Status: strings.Repeat("s", 64),
				StorageNodes: maximumPositiveCapacityRoles, GatewayNodes: maximumPositiveCapacityRoles,
			})
		}
		if i < maximumReportedBlockErrors {
			status.BlockErrorDetails.TopErrors = append(status.BlockErrorDetails.TopErrors, garagev1beta2.BlockErrorDetail{
				BlockHash: strings.Repeat("b", 64), ErrorCount: int32(^uint32(0) >> 1),
				LastError: strings.Repeat("e", 256), LastAttempt: &observedAt, NextRetry: &observedAt,
			})
		}
		status.RemoteClusters = append(status.RemoteClusters, garagev1beta2.RemoteClusterStatus{
			Name: fmt.Sprintf("remote-%056d", i), Zone: strings.Repeat("z", 63),
			Nodes: maximumPositiveCapacityRoles, HealthyNodes: maximumPositiveCapacityRoles,
			LastSeen: &observedAt,
		})
		status.PendingGatewayTombstones = append(status.PendingGatewayTombstones, nodeID)
		status.UnreachablePeers = append(status.UnreachablePeers, fmt.Sprintf("%.16s (down 2562047h47m)", nodeID))
		status.GatewayNodesNotInLayout = append(status.GatewayNodesNotInLayout,
			fmt.Sprintf("%s-%03d", strings.Repeat("g", 59), i))
	}
	for _, conditionType := range garageClusterConditionTypes {
		status.Conditions = append(status.Conditions, metav1.Condition{
			Type: conditionType, Status: metav1.ConditionFalse,
			ObservedGeneration: int64(^uint64(0) >> 1), LastTransitionTime: observedAt,
			Reason: strings.Repeat("R", 64), Message: strings.Repeat("m", statusConditionMessageLimit),
		})
	}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "maximum-members", Namespace: membershipTestNamespace},
		Status:     status,
	}
	encodedStatus, err := json.Marshal(cluster.Status)
	if err != nil {
		t.Fatal(err)
	}
	encodedObject, err := json.Marshal(cluster)
	if err != nil {
		t.Fatal(err)
	}
	encodedDrain, err := json.Marshal(drain)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("projected storage-drain transaction: %d bytes; full coexisting GarageCluster.status envelope: %d bytes (minimal enclosing object: %d bytes)",
		len(encodedDrain), len(encodedStatus), len(encodedObject))
	if len(encodedDrain) > drainTransactionBudget {
		t.Fatalf("projected storage-drain transaction is %d bytes, above the %d-byte feature budget", len(encodedDrain), drainTransactionBudget)
	}
	if len(encodedStatus) > statusSafetyBudget {
		t.Fatalf("projected full GarageCluster.status is %d bytes, above the %d-byte release budget", len(encodedStatus), statusSafetyBudget)
	}
}
