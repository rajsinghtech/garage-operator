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
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	siteRoleTestNS       = "site-role"
	siteRoleTestNodeID   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	siteRoleTestClusterU = "site-role-cluster-uid"
)

func siteRoleScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		appsv1.AddToScheme, corev1.AddToScheme, garagev1beta1.AddToScheme, garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}

func siteRoleCluster(name string, role garagev1beta2.LayoutSiteRole) *garagev1beta2.GarageCluster {
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: siteRoleTestNS, UID: types.UID(siteRoleTestClusterU), Generation: 3,
		},
	}
	if role != "" {
		cluster.Spec.LayoutManagement = &garagev1beta2.LayoutManagementConfig{SiteRole: role}
		if role == garagev1beta2.LayoutSiteRoleFollower {
			cluster.Spec.RemoteClusters = []garagev1beta2.RemoteClusterConfig{{Name: "writer"}}
		}
	}
	return cluster
}

// layoutWriteRecorder is a Garage Admin API double that serves a fixed layout
// and records every request that would change it.
type layoutWriteRecorder struct {
	mu     sync.Mutex
	writes []string
	reads  []string
	layout garage.ClusterLayout
	server *httptest.Server
}

func newLayoutWriteRecorder(t *testing.T, layout garage.ClusterLayout) *layoutWriteRecorder {
	t.Helper()
	recorder := &layoutWriteRecorder{layout: layout}
	recorder.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.mu.Lock()
		defer recorder.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case pathUpdateLayout, pathApplyLayout, "/v2/RevertClusterLayout", testSkipDeadNodesPath:
			recorder.writes = append(recorder.writes, r.URL.Path)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		case pathGetClusterLayout:
			recorder.reads = append(recorder.reads, r.URL.Path)
			_ = json.NewEncoder(w).Encode(recorder.layout)
		case pathGetClusterStatus:
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{LayoutVersion: recorder.layout.Version})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(func() {
		recorder.server.CloseClientConnections()
		recorder.server.Close()
	})
	return recorder
}

func (l *layoutWriteRecorder) writeCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.writes)
}

func (l *layoutWriteRecorder) client() *garage.Client {
	return garage.NewClient(l.server.URL, "token")
}

func TestWithLayoutSiteGuard(t *testing.T) {
	t.Parallel()
	scheme := siteRoleScheme(t)
	writer := siteRoleCluster("writer", garagev1beta2.LayoutSiteRoleWriter)
	follower := siteRoleCluster("follower", garagev1beta2.LayoutSiteRoleFollower)
	unset := siteRoleCluster("unset", "")
	edgeOf := func(name, owner string) *garagev1beta2.GarageCluster {
		edge := siteRoleCluster(name, "")
		edge.Spec.Gateway = &garagev1beta2.GatewaySpec{Replicas: 1}
		edge.Spec.ConnectTo = &garagev1beta2.ConnectToConfig{ClusterRef: &garagev1beta2.ClusterReference{Name: owner}}
		return edge
	}
	edgeFollower, edgeWriter := edgeOf("edge-follower", follower.Name), edgeOf("edge-writer", writer.Name)
	reader := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(writer, follower, unset, edgeFollower, edgeWriter).Build()

	tests := []struct {
		name    string
		cluster *garagev1beta2.GarageCluster
		blocked bool
	}{
		{"writer is not guarded", writer, false},
		{"unset siteRole is not guarded", unset, false},
		{"follower is guarded", follower, true},
		{"edge gateway of a follower owner is guarded", edgeFollower, true},
		{"edge gateway of a writer owner is not guarded", edgeWriter, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := withLayoutSiteGuard(context.Background(), reader, tt.cluster)
			if got := garage.LayoutWritesDisabled(ctx); got != tt.blocked {
				t.Fatalf("LayoutWritesDisabled = %v, want %v", got, tt.blocked)
			}
			if got := layoutWritesBlocked(ctx); got != tt.blocked {
				t.Fatalf("layoutWritesBlocked = %v, want %v", got, tt.blocked)
			}
		})
	}
	if ctx := withLayoutSiteGuard(context.Background(), reader, nil); garage.LayoutWritesDisabled(ctx) {
		t.Fatal("nil cluster must not be guarded")
	}
}

func TestGuardedContextRefusesAllLayoutWritesWithoutHTTP(t *testing.T) {
	t.Parallel()
	server := newLayoutWriteRecorder(t, garage.ClusterLayout{Version: 1})
	follower := siteRoleCluster("follower", garagev1beta2.LayoutSiteRoleFollower)
	ctx := withLayoutSiteGuardForOwner(context.Background(), follower, nil)
	c := server.client()

	_, skipErr := c.ClusterLayoutSkipDeadNodes(ctx, garage.SkipDeadNodesRequest{Version: 2})
	errs := []error{
		skipErr,
		c.UpdateClusterLayout(ctx, []garage.NodeRoleChange{{ID: siteRoleTestNodeID, Remove: true}}),
		c.ApplyClusterLayout(ctx, 2),
		c.RevertClusterLayout(ctx),
	}
	for i, err := range errs {
		if !errors.Is(err, garage.ErrLayoutWritesDisabled) || !errors.Is(err, errLayoutMutationPending) {
			t.Fatalf("write %d error = %v, want it to match both ErrLayoutWritesDisabled and errLayoutMutationPending", i, err)
		}
	}
	if server.writeCount() != 0 {
		t.Fatalf("follower issued %d layout write request(s): %v", server.writeCount(), server.writes)
	}
	if got := testutil.ToFloat64(layoutWriteBlockedTotal.WithLabelValues(layoutSiteLabel(follower), garage.LayoutOpApply)); got < 1 {
		t.Fatalf("blocked-write metric = %v, want >= 1", got)
	}
	// Reads stay available so the follower can observe the shared layout.
	if _, err := c.GetClusterLayout(ctx); err != nil {
		t.Fatalf("read refused under follower guard: %v", err)
	}
}

func TestApplyLayoutWriterRole(t *testing.T) {
	t.Parallel()
	t.Run("unset clears everything", func(t *testing.T) {
		t.Parallel()
		cluster := siteRoleCluster("unset", "")
		cluster.Status.LayoutWriter = &garagev1beta2.LayoutWriterStatus{Role: garagev1beta2.LayoutSiteRoleWriter}
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type: garagev1beta1.ConditionLayoutWriter, Status: metav1.ConditionTrue, Reason: "x",
		})
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type: garagev1beta1.ConditionAwaitingLayoutWriter, Status: metav1.ConditionTrue, Reason: "x",
		})
		applyLayoutWriterRole(cluster)
		if cluster.Status.LayoutWriter != nil || len(cluster.Status.Conditions) != 0 {
			t.Fatalf("status not cleared: %+v %+v", cluster.Status.LayoutWriter, cluster.Status.Conditions)
		}
	})
	t.Run("writer", func(t *testing.T) {
		t.Parallel()
		cluster := siteRoleCluster("writer", garagev1beta2.LayoutSiteRoleWriter)
		applyLayoutWriterRole(cluster)
		if cluster.Status.LayoutWriter == nil || cluster.Status.LayoutWriter.Role != garagev1beta2.LayoutSiteRoleWriter {
			t.Fatalf("status.layoutWriter = %+v", cluster.Status.LayoutWriter)
		}
		cond := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionLayoutWriter)
		if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != garagev1beta1.ReasonWriterSite ||
			cond.ObservedGeneration != cluster.Generation {
			t.Fatalf("LayoutWriter condition = %+v", cond)
		}
		if meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionAwaitingLayoutWriter) != nil {
			t.Fatal("a writer must never carry AwaitingLayoutWriter")
		}
	})
	t.Run("follower", func(t *testing.T) {
		t.Parallel()
		cluster := siteRoleCluster("follower", garagev1beta2.LayoutSiteRoleFollower)
		applyLayoutWriterRole(cluster)
		if cluster.Status.LayoutWriter == nil || cluster.Status.LayoutWriter.Role != garagev1beta2.LayoutSiteRoleFollower {
			t.Fatalf("status.layoutWriter = %+v", cluster.Status.LayoutWriter)
		}
		cond := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionLayoutWriter)
		if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != garagev1beta1.ReasonFollowerSite {
			t.Fatalf("LayoutWriter condition = %+v", cond)
		}
	})
}

func TestComputeAndApplyAwaitingLayoutWriter(t *testing.T) {
	t.Parallel()
	follower := siteRoleCluster("follower", garagev1beta2.LayoutSiteRoleFollower)
	now := metav1.Now()
	node := func(name, id string, inLayout bool, deleting bool) garagev1beta1.GarageNode {
		n := garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: siteRoleTestNS},
			Spec:       garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: follower.Name}},
			Status:     garagev1beta1.GarageNodeStatus{NodeID: id, InLayout: inLayout},
		}
		if deleting {
			n.DeletionTimestamp = &now
		}
		return n
	}
	other := node("other", siteRoleTestNodeID, false, false)
	other.Spec.ClusterRef.Name = "another-cluster"

	t.Run("nothing pending", func(t *testing.T) {
		t.Parallel()
		cluster := follower.DeepCopy()
		awaiting := computeLayoutWriterAwaiting(cluster, []garagev1beta1.GarageNode{
			node("ok", siteRoleTestNodeID, true, false), node("starting", "", false, false), other,
		}, nil, false)
		previous, current := applyAwaitingLayoutWriter(cluster, awaiting)
		if previous != "" || current != "" {
			t.Fatalf("previous=%q current=%q", previous, current)
		}
		cond := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionAwaitingLayoutWriter)
		if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != garagev1beta1.ReasonNothingPending {
			t.Fatalf("condition = %+v", cond)
		}
	})
	t.Run("role removal outranks the rest", func(t *testing.T) {
		t.Parallel()
		cluster := follower.DeepCopy()
		cluster.Status.PendingGatewayTombstones = []string{"stale"}
		awaiting := computeLayoutWriterAwaiting(cluster, []garagev1beta1.GarageNode{
			node("leaving", siteRoleTestNodeID, true, true), node("new", siteRoleTestNodeID, false, false),
		}, nil, false)
		_, current := applyAwaitingLayoutWriter(cluster, awaiting)
		if current != garagev1beta1.ReasonPendingRoleRemoval {
			t.Fatalf("primary reason = %q", current)
		}
		cond := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionAwaitingLayoutWriter)
		for _, want := range []string{"leaving", "new", "stale gateway layout"} {
			if cond == nil || !strings.Contains(cond.Message, want) {
				t.Fatalf("message %v lacks %q", cond, want)
			}
		}
	})
	t.Run("nodes without role", func(t *testing.T) {
		t.Parallel()
		cluster := follower.DeepCopy()
		awaiting := computeLayoutWriterAwaiting(cluster, []garagev1beta1.GarageNode{node("new", siteRoleTestNodeID, false, false)}, nil, false)
		if _, current := applyAwaitingLayoutWriter(cluster, awaiting); current != garagev1beta1.ReasonNodesWithoutRole {
			t.Fatalf("primary reason = %q", current)
		}
	})
	t.Run("pending tombstones", func(t *testing.T) {
		t.Parallel()
		cluster := follower.DeepCopy()
		cluster.Status.PendingGatewayTombstones = []string{"stale"}
		awaiting := computeLayoutWriterAwaiting(cluster, nil, nil, false)
		if _, current := applyAwaitingLayoutWriter(cluster, awaiting); current != garagev1beta1.ReasonPendingTombstones {
			t.Fatalf("primary reason = %q", current)
		}
	})
	t.Run("replication change", func(t *testing.T) {
		t.Parallel()
		cluster := follower.DeepCopy()
		cluster.Spec.Replication = &garagev1beta2.ReplicationConfig{ZoneRedundancyMode: "Maximum"}
		live := &garage.LayoutParameters{ZoneRedundancy: &garage.ZoneRedundancy{AtLeast: ptrTo(2)}}
		awaiting := computeLayoutWriterAwaiting(cluster, nil, live, true)
		if _, current := applyAwaitingLayoutWriter(cluster, awaiting); current != garagev1beta1.ReasonReplicationChange {
			t.Fatalf("primary reason = %q", current)
		}
		same := computeLayoutWriterAwaiting(cluster, nil, &garage.LayoutParameters{ZoneRedundancy: &garage.ZoneRedundancy{Maximum: true}}, true)
		if same.primary() != "" {
			t.Fatalf("matching parameters still awaiting: %q", same.primary())
		}
		unknown := computeLayoutWriterAwaiting(cluster, nil, nil, false)
		if unknown.primary() != "" {
			t.Fatalf("unreadable layout must not report a replication change: %q", unknown.primary())
		}
	})
	t.Run("reports transitions", func(t *testing.T) {
		t.Parallel()
		cluster := follower.DeepCopy()
		pending := computeLayoutWriterAwaiting(cluster, []garagev1beta1.GarageNode{node("new", siteRoleTestNodeID, false, false)}, nil, false)
		if previous, current := applyAwaitingLayoutWriter(cluster, pending); previous != "" || current == "" {
			t.Fatalf("first apply previous=%q current=%q", previous, current)
		}
		if previous, current := applyAwaitingLayoutWriter(cluster, layoutWriterAwaiting{}); previous != garagev1beta1.ReasonNodesWithoutRole || current != "" {
			t.Fatalf("resolve previous=%q current=%q", previous, current)
		}
	})
	t.Run("never applied to a writer", func(t *testing.T) {
		t.Parallel()
		writer := siteRoleCluster("writer", garagev1beta2.LayoutSiteRoleWriter)
		meta.SetStatusCondition(&writer.Status.Conditions, metav1.Condition{
			Type: garagev1beta1.ConditionAwaitingLayoutWriter, Status: metav1.ConditionTrue, Reason: "stale",
		})
		applyAwaitingLayoutWriter(writer, layoutWriterAwaiting{})
		if meta.FindStatusCondition(writer.Status.Conditions, garagev1beta1.ConditionAwaitingLayoutWriter) != nil {
			t.Fatal("writer kept the AwaitingLayoutWriter condition")
		}
	})
}

func TestZoneRedundancyDiffers(t *testing.T) {
	t.Parallel()
	two := 2
	three := 3
	tests := []struct {
		name    string
		desired *garage.ZoneRedundancy
		live    *garage.LayoutParameters
		want    bool
	}{
		{"unset desired never differs", nil, &garage.LayoutParameters{}, false},
		{"no live value differs", &garage.ZoneRedundancy{Maximum: true}, nil, true},
		{"maximum equal", &garage.ZoneRedundancy{Maximum: true}, &garage.LayoutParameters{ZoneRedundancy: &garage.ZoneRedundancy{Maximum: true}}, false},
		{"maximum vs atLeast", &garage.ZoneRedundancy{Maximum: true}, &garage.LayoutParameters{ZoneRedundancy: &garage.ZoneRedundancy{AtLeast: &two}}, true},
		{"atLeast equal", &garage.ZoneRedundancy{AtLeast: &two}, &garage.LayoutParameters{ZoneRedundancy: &garage.ZoneRedundancy{AtLeast: &two}}, false},
		{"atLeast differs", &garage.ZoneRedundancy{AtLeast: &three}, &garage.LayoutParameters{ZoneRedundancy: &garage.ZoneRedundancy{AtLeast: &two}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := zoneRedundancyDiffers(tt.desired, tt.live); got != tt.want {
				t.Fatalf("zoneRedundancyDiffers = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBlockLayoutAnnotationsOnFollowerConsumesRequests(t *testing.T) {
	t.Parallel()
	scheme := siteRoleScheme(t)
	follower := siteRoleCluster("follower-annotations", garagev1beta2.LayoutSiteRoleFollower)
	follower.Annotations = map[string]string{
		garagev1beta1.AnnotationRevertLayout:       annotationTrue,
		garagev1beta1.AnnotationSkipDeadNodes:      annotationTrue,
		garagev1beta1.AnnotationAllowMissingData:   annotationTrue,
		garagev1beta1.AnnotationPurgeClusterLayout: annotationTrue,
		"unrelated": "keep",
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).WithObjects(follower).Build()
	if err := kubeClient.Get(context.Background(), clientKey(follower), follower); err != nil {
		t.Fatal(err)
	}
	events := record.NewFakeRecorder(8)
	reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient, EventRecorder: events}

	consumed, err := reconciler.blockLayoutAnnotationsOnFollower(context.Background(), follower)
	if err != nil || !consumed {
		t.Fatalf("consumed=%v err=%v", consumed, err)
	}
	stored := &garagev1beta2.GarageCluster{}
	if err := kubeClient.Get(context.Background(), clientKey(follower), stored); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored.Annotations, map[string]string{"unrelated": "keep"}) {
		t.Fatalf("annotations = %v", stored.Annotations)
	}
	last := stored.Status.LastOperation
	if last == nil || last.Succeeded || !strings.Contains(last.Error, "Follower") ||
		!strings.Contains(last.Type, "RevertLayout") || !strings.Contains(last.Type, "SkipDeadNodes") {
		t.Fatalf("lastOperation = %+v", last)
	}
	select {
	case event := <-events.Events:
		if !strings.Contains(event, "Warning") || !strings.Contains(event, eventReasonLayoutWriteBlocked) {
			t.Fatalf("event = %q", event)
		}
	default:
		t.Fatal("no LayoutWriteBlocked event emitted")
	}
	if got := testutil.ToFloat64(layoutWriteBlockedTotal.WithLabelValues(layoutSiteLabel(follower), "annotation:RevertLayout")); got < 1 {
		t.Fatalf("blocked metric = %v", got)
	}

	consumed, err = reconciler.blockLayoutAnnotationsOnFollower(context.Background(), stored)
	if err != nil || consumed {
		t.Fatalf("second pass consumed=%v err=%v, want nothing to do", consumed, err)
	}
}

func TestFollowerRemoveNodesFromLayoutHoldsUntilWriterRemovesRoles(t *testing.T) {
	t.Parallel()
	cap10 := uint64(10 << 30)
	server := newLayoutWriteRecorder(t, garage.ClusterLayout{Version: 4, Roles: []garage.LayoutNodeRole{{
		ID: siteRoleTestNodeID, Zone: testZone, Capacity: &cap10,
		Tags: []string{"cluster-uid:" + siteRoleTestClusterU},
	}}})
	follower := siteRoleCluster("follower-delete", garagev1beta2.LayoutSiteRoleFollower)
	ctx := withLayoutSiteGuardForOwner(context.Background(), follower, nil)
	reconciler := &GarageClusterReconciler{LayoutMutations: NewLayoutMutationCoordinator()}

	err := reconciler.removeNodesFromLayoutLocked(ctx, follower, nil, server.client())
	if !errors.Is(err, garage.ErrLayoutWritesDisabled) || !errors.Is(err, errLayoutMutationPending) {
		t.Fatalf("err = %v, want an awaiting-layout-writer error", err)
	}
	if layoutWriterAwaitReason(err) != garagev1beta1.ReasonPendingRoleRemoval {
		t.Fatalf("await reason = %q", layoutWriterAwaitReason(err))
	}
	if server.writeCount() != 0 {
		t.Fatalf("follower wrote to the layout: %v", server.writes)
	}
}

func TestFollowerGarageNodeFinalizeWaitsForWriter(t *testing.T) {
	t.Parallel()
	scheme := siteRoleScheme(t)
	follower := siteRoleCluster("follower-node", garagev1beta2.LayoutSiteRoleFollower)
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "leaving", Namespace: siteRoleTestNS, UID: "node-uid"},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: follower.Name}, Gateway: true, Zone: testZone,
		},
		Status: garagev1beta1.GarageNodeStatus{NodeID: siteRoleTestNodeID, InLayout: true},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta1.GarageNode{}).WithObjects(node).Build()
	reconciler := &GarageNodeReconciler{Client: kubeClient, Scheme: scheme}
	ctx := withLayoutSiteGuardForOwner(context.Background(), follower, nil)

	t.Run("role present waits and writes nothing", func(t *testing.T) {
		t.Parallel()
		server := newLayoutWriteRecorder(t, garage.ClusterLayout{Version: 2, Roles: []garage.LayoutNodeRole{{
			ID: siteRoleTestNodeID, Zone: testZone,
		}}})
		err := reconciler.finalize(ctx, node.DeepCopy(), follower, server.client())
		if !errors.Is(err, garage.ErrLayoutWritesDisabled) || !errors.Is(err, errLayoutMutationPending) {
			t.Fatalf("err = %v, want an awaiting-layout-writer error", err)
		}
		if layoutWriterAwaitReason(err) != garagev1beta1.ReasonPendingRoleRemoval {
			t.Fatalf("await reason = %q", layoutWriterAwaitReason(err))
		}
		if server.writeCount() != 0 {
			t.Fatalf("follower wrote to the layout: %v", server.writes)
		}
	})
	t.Run("role removed by the writer releases", func(t *testing.T) {
		t.Parallel()
		server := newLayoutWriteRecorder(t, garage.ClusterLayout{Version: 3})
		cluster := follower.DeepCopy()
		if err := reconciler.finalize(ctx, node.DeepCopy(), cluster, server.client()); err != nil {
			t.Fatalf("finalize after the writer removed the role: %v", err)
		}
		if server.writeCount() != 0 {
			t.Fatalf("follower wrote to the layout: %v", server.writes)
		}
	})
}

// TestFollowerReconcileNodeNeverStagesRole drives an external GarageNode, the
// shape a Writer uses to declare a follower site's node, through reconcileNode
// under both roles. The Writer stages the role; the Follower holds back.
func TestFollowerReconcileNodeNeverStagesRole(t *testing.T) {
	t.Parallel()
	scheme := siteRoleScheme(t)
	run := func(t *testing.T, role garagev1beta2.LayoutSiteRole) (*layoutWriteRecorder, error) {
		t.Helper()
		server := newLayoutWriteRecorder(t, garage.ClusterLayout{Version: 1})
		cluster := siteRoleCluster("reconcile-"+strings.ToLower(string(role)), role)
		cluster.Spec.Admin = &garagev1beta2.AdminConfig{BindPort: int32(server.server.Listener.Addr().(*net.TCPAddr).Port)}
		capacity := resource.MustParse("10Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "ext-" + strings.ToLower(string(role)), Namespace: siteRoleTestNS, UID: "ext-uid", Generation: 1},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
				NodeID:     siteRoleTestNodeID,
				Zone:       "remote-zone",
				Capacity:   &capacity,
				External:   &garagev1beta1.ExternalNodeConfig{Address: "10.0.0.9", Port: 3901},
			},
			// An already observed identity skips the first-observation boundary.
			Status: garagev1beta1.GarageNodeStatus{NodeID: siteRoleTestNodeID},
		}
		kubeClient := fake.NewClientBuilder().WithScheme(scheme).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).WithObjects(node).Build()
		reconciler := &GarageNodeReconciler{Client: kubeClient, Scheme: scheme}
		ctx := withLayoutSiteGuardForOwner(context.Background(), cluster, nil)
		return server, reconciler.reconcileNode(ctx, node, cluster, server.client(), cluster)
	}

	t.Run("follower waits", func(t *testing.T) {
		t.Parallel()
		server, err := run(t, garagev1beta2.LayoutSiteRoleFollower)
		if !errors.Is(err, garage.ErrLayoutWritesDisabled) || !errors.Is(err, errLayoutMutationPending) {
			t.Fatalf("err = %v, want an awaiting-layout-writer error", err)
		}
		if layoutWriterAwaitReason(err) != garagev1beta1.ReasonNodesWithoutRole {
			t.Fatalf("await reason = %q", layoutWriterAwaitReason(err))
		}
		if server.writeCount() != 0 {
			t.Fatalf("follower wrote to the layout: %v", server.writes)
		}
	})
	t.Run("writer is unchanged", func(t *testing.T) {
		t.Parallel()
		server, _ := run(t, garagev1beta2.LayoutSiteRoleWriter)
		if server.writeCount() == 0 {
			t.Fatal("writer did not stage the external node role; the follower check would be vacuous")
		}
		if server.writes[0] != pathUpdateLayout {
			t.Fatalf("first write = %q, want %q", server.writes[0], pathUpdateLayout)
		}
	})
}

func TestFollowerGatewayTombstonesAreRecordedNotRemoved(t *testing.T) {
	t.Parallel()
	const (
		clusterUID = "follower-reaper-uid"
		retiredID  = "retired-follower-gateway-id"
	)
	roles := []garage.LayoutNodeRole{{
		ID: retiredID, Zone: testZone,
		Tags: []string{testEdgeOwnershipTag, "cluster-uid:" + clusterUID, testTierGatewayTag, "edge-gateway-1"},
	}}
	downFor := uint64(peerUnreachableThreshold.Seconds()) + 3600
	var mu sync.Mutex
	var writes []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case pathGetClusterStatus:
			_ = json.NewEncoder(w).Encode(garage.ClusterStatus{LayoutVersion: 4, Nodes: []garage.NodeInfo{{
				ID: retiredID, IsUp: false, LastSeenSecsAgo: &downFor,
			}}})
		case pathGetLayoutHistory:
			_ = json.NewEncoder(w).Encode(garage.LayoutHistoryResponse{
				CurrentVersion: 4, Versions: []garage.LayoutVersion{{Version: 4, Status: garage.LayoutVersionStatusCurrent}},
			})
		case pathGetClusterLayout:
			_ = json.NewEncoder(w).Encode(garage.ClusterLayout{Version: 4, Roles: roles})
		case pathUpdateLayout, pathApplyLayout, testSkipDeadNodesPath:
			writes = append(writes, r.URL.Path)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	scheme := siteRoleScheme(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testExternalAdminSecretName, Namespace: siteRoleTestNS},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte("token")},
	}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testEdgeValue, Namespace: siteRoleTestNS, UID: types.UID(clusterUID)},
		Spec: garagev1beta2.GarageClusterSpec{
			Zone: testZone, Gateway: &garagev1beta2.GatewaySpec{Replicas: 1},
			LayoutManagement: &garagev1beta2.LayoutManagementConfig{AutoApply: true, SiteRole: garagev1beta2.LayoutSiteRoleFollower},
			ConnectTo: &garagev1beta2.ConnectToConfig{
				AdminAPIEndpoint:    server.URL,
				AdminTokenSecretRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: secret.Name}},
			},
		},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).WithObjects(secret, cluster).Build()
	if err := kubeClient.Get(context.Background(), clientKey(cluster), cluster); err != nil {
		t.Fatal(err)
	}
	reconciler := &GarageClusterReconciler{Client: kubeClient, APIReader: kubeClient, Scheme: scheme, LayoutMutations: NewLayoutMutationCoordinator()}
	ctx := withLayoutSiteGuardForOwner(context.Background(), cluster, nil)

	reconciler.reconcileGatewayTombstones(ctx, cluster)

	mu.Lock()
	defer mu.Unlock()
	if len(writes) != 0 {
		t.Fatalf("follower removed a gateway layout entry: %v", writes)
	}
	if got := cluster.Status.PendingGatewayTombstones; !reflect.DeepEqual(got, []string{retiredID}) {
		t.Fatalf("pending tombstones = %v, want the stale entry recorded for the writer", got)
	}
}
