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
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func TestParsePurgeAnnotation(t *testing.T) {
	tests := []struct {
		in      string
		factor  int
		force   bool
		wantErr bool
	}{
		{fmFactor2, 2, false, false},
		{"factor=1,force", 1, true, false},
		{"force,factor=3", 3, true, false},
		{"factor=0", 0, false, true},
		{"factor=-1", 0, false, true},
		{"factor=abc", 0, false, true},
		{"", 0, false, true},
		{"force", 0, false, true},
		{"foo=bar", 0, false, true},
	}
	for _, tt := range tests {
		f, force, err := parsePurgeAnnotation(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parsePurgeAnnotation(%q) err=%v, wantErr=%v", tt.in, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && (f != tt.factor || force != tt.force) {
			t.Errorf("parsePurgeAnnotation(%q) = (%d,%v), want (%d,%v)", tt.in, f, force, tt.factor, tt.force)
		}
	}
}

func fmScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := appsv1.AddToScheme(s); err != nil {
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

const (
	fmNS      = "fm-test"
	fmFactor2 = "factor=2"
)

func fmCluster(name string, mutators ...func(*garagev1beta2.GarageCluster)) *garagev1beta2.GarageCluster {
	c := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   fmNS,
			Annotations: map[string]string{},
		},
		Spec: garagev1beta2.GarageClusterSpec{
			LayoutPolicy: LayoutPolicyAuto,
			Zone:         "z",
			Replication:  &garagev1beta2.ReplicationConfig{Factor: 2},
			Storage: &garagev1beta2.StorageSpec{
				Replicas: 3,
				Metadata: &garagev1beta2.VolumeConfig{Size: ptr.To(resource.MustParse("1Gi"))},
				Data:     &garagev1beta2.VolumeConfig{Size: ptr.To(resource.MustParse("10Gi"))},
			},
		},
	}
	for _, m := range mutators {
		m(c)
	}
	return c
}

// fmStorageNode builds an operator-owned storage GarageNode for ordinal i.
func fmStorageNode(cluster string, i int, nodeID string) *garagev1beta1.GarageNode {
	name := autoModeGarageNodeName(cluster, int32(i))
	return &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: fmNS,
			Labels: map[string]string{
				labelCluster:      cluster,
				labelTier:         tierStorage,
				labelAppManagedBy: managedByOperatorValue,
			},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster},
			Zone:       "z",
			Capacity:   ptr.To(resource.MustParse("10Gi")),
			Tags:       []string{"tier:storage"},
		},
		Status: garagev1beta1.GarageNodeStatus{NodeID: nodeID},
	}
}

func fmBuild(t *testing.T, objs ...client.Object) *GarageClusterReconciler {
	t.Helper()
	s := fmScheme(t)
	b := fake.NewClientBuilder().WithScheme(s).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}, &garagev1beta1.GarageNode{}).
		WithObjects(objs...)
	return &GarageClusterReconciler{Client: b.Build(), Scheme: s}
}

func TestFactorMigration_ValidationGuards(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		mutate  func(*garagev1beta2.GarageCluster)
		extra   []client.Object
		wantMsg string
	}{
		{
			name: "factor mismatch",
			mutate: func(c *garagev1beta2.GarageCluster) {
				c.Annotations[garagev1beta1.AnnotationPurgeClusterLayout] = fmFactor2
				c.Spec.Replication.Factor = 3
			},
			wantMsg: "must match spec.replication.factor",
		},
		{
			name: "manual mode refused",
			mutate: func(c *garagev1beta2.GarageCluster) {
				c.Annotations[garagev1beta1.AnnotationPurgeClusterLayout] = fmFactor2
				c.Spec.Replication.Factor = 2
				c.Spec.LayoutPolicy = LayoutPolicyManual
			},
			wantMsg: "only supported in Auto",
		},
		{
			name: "federation refused",
			mutate: func(c *garagev1beta2.GarageCluster) {
				c.Annotations[garagev1beta1.AnnotationPurgeClusterLayout] = fmFactor2
				c.Spec.Replication.Factor = 2
				c.Spec.RemoteClusters = []garagev1beta2.RemoteClusterConfig{{Name: "r"}}
			},
			wantMsg: "refused while spec.remoteClusters",
		},
		{
			name: "dangerous without force",
			mutate: func(c *garagev1beta2.GarageCluster) {
				c.Annotations[garagev1beta1.AnnotationPurgeClusterLayout] = fmFactor2
				c.Spec.Replication.Factor = 2
				c.Spec.Replication.ConsistencyMode = "dangerous"
			},
			wantMsg: "requires ,force",
		},
		{
			name: "insufficient nodes",
			mutate: func(c *garagev1beta2.GarageCluster) {
				c.Annotations[garagev1beta1.AnnotationPurgeClusterLayout] = "factor=5"
				c.Spec.Replication.Factor = 5
			},
			wantMsg: "storage nodes < requested factor",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fmCluster("c1", tt.mutate)
			objs := []client.Object{c}
			// 3 storage nodes (so "insufficient nodes" only trips for factor=5).
			for i := 0; i < 3; i++ {
				objs = append(objs, fmStorageNode("c1", i, "id"+string(rune('a'+i))))
			}
			objs = append(objs, tt.extra...)
			r := fmBuild(t, objs...)

			if _, err := r.reconcileFactorMigration(ctx, c); err != nil {
				t.Fatalf("reconcileFactorMigration: %v", err)
			}
			got := &garagev1beta2.GarageCluster{}
			_ = r.Get(ctx, types.NamespacedName{Name: "c1", Namespace: fmNS}, got)
			if got.Status.FactorMigration == nil || got.Status.FactorMigration.Phase != fmPhaseFailed {
				t.Fatalf("expected Failed phase, got %+v", got.Status.FactorMigration)
			}
			if !strings.Contains(got.Status.FactorMigration.Message, tt.wantMsg) {
				t.Fatalf("message %q does not contain %q", got.Status.FactorMigration.Message, tt.wantMsg)
			}
			// On validation failure the annotation must be removed.
			if _, ok := got.Annotations[garagev1beta1.AnnotationPurgeClusterLayout]; ok {
				t.Fatal("expected purge annotation to be removed after validation failure")
			}
		})
	}
}

func TestFactorMigration_ValidationPassAdvancesToScalingDown(t *testing.T) {
	ctx := context.Background()
	c := fmCluster("c2", func(c *garagev1beta2.GarageCluster) {
		c.Annotations[garagev1beta1.AnnotationPurgeClusterLayout] = fmFactor2
	})
	objs := []client.Object{c}
	for i := 0; i < 3; i++ {
		objs = append(objs, fmStorageNode("c2", i, "id"+string(rune('a'+i))))
	}
	r := fmBuild(t, objs...)

	if _, err := r.reconcileFactorMigration(ctx, c); err != nil {
		t.Fatalf("reconcileFactorMigration: %v", err)
	}
	got := &garagev1beta2.GarageCluster{}
	_ = r.Get(ctx, types.NamespacedName{Name: "c2", Namespace: fmNS}, got)
	if got.Status.FactorMigration == nil || got.Status.FactorMigration.Phase != fmPhaseScalingDown {
		t.Fatalf("expected ScalingDown, got %+v", got.Status.FactorMigration)
	}
	if got.Status.FactorMigration.PurgeID == "" {
		t.Fatal("expected PurgeID to be set")
	}
	if got.Status.FactorMigration.ToFactor != 2 {
		t.Fatalf("expected ToFactor=2, got %d", got.Status.FactorMigration.ToFactor)
	}
}

func TestFactorMigration_ScaleDownSuspendsAndScales(t *testing.T) {
	ctx := context.Background()
	c := fmCluster("c3")
	c.Status.FactorMigration = &garagev1beta2.FactorMigrationStatus{
		Phase: fmPhaseScalingDown, ToFactor: 2, PurgeID: "p1", StartedAt: ptr.To(metav1.Now()),
	}
	objs := []client.Object{c}
	for i := 0; i < 3; i++ {
		objs = append(objs, fmStorageNode("c3", i, "id"+string(rune('a'+i))))
		objs = append(objs, &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: autoModeGarageNodeName("c3", int32(i)), Namespace: fmNS},
			Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To(int32(1))},
		})
	}
	r := fmBuild(t, objs...)

	// No storage pods exist → should advance to Purging after suspending + scaling.
	if _, err := r.reconcileFactorMigration(ctx, c); err != nil {
		t.Fatalf("reconcileFactorMigration: %v", err)
	}

	// All storage nodes suspended with the PurgeID.
	for i := 0; i < 3; i++ {
		n := &garagev1beta1.GarageNode{}
		_ = r.Get(ctx, types.NamespacedName{Name: autoModeGarageNodeName("c3", int32(i)), Namespace: fmNS}, n)
		if n.Annotations[garagev1beta1.AnnotationOperatorSuspended] != "p1" {
			t.Fatalf("node %d not suspended with PurgeID, got %q", i, n.Annotations[garagev1beta1.AnnotationOperatorSuspended])
		}
		sts := &appsv1.StatefulSet{}
		_ = r.Get(ctx, types.NamespacedName{Name: autoModeGarageNodeName("c3", int32(i)), Namespace: fmNS}, sts)
		if sts.Spec.Replicas == nil || *sts.Spec.Replicas != 0 {
			t.Fatalf("STS %d not scaled to 0", i)
		}
	}
	got := &garagev1beta2.GarageCluster{}
	_ = r.Get(ctx, types.NamespacedName{Name: "c3", Namespace: fmNS}, got)
	if got.Status.FactorMigration.Phase != fmPhasePurging {
		t.Fatalf("expected Purging (no pods present), got %s", got.Status.FactorMigration.Phase)
	}
}

func TestFactorMigration_ScaleDownWaitsWhilePodsExist(t *testing.T) {
	ctx := context.Background()
	c := fmCluster("c4")
	c.Status.FactorMigration = &garagev1beta2.FactorMigrationStatus{
		Phase: fmPhaseScalingDown, ToFactor: 2, PurgeID: "p1", StartedAt: ptr.To(metav1.Now()),
	}
	objs := make([]client.Object, 0, 4)
	objs = append(objs, c, fmStorageNode("c4", 0, "ida"))
	objs = append(objs, &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: autoModeGarageNodeName("c4", 0), Namespace: fmNS},
		Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To(int32(1))},
	})
	// A lingering storage pod must hold the migration in ScalingDown.
	objs = append(objs, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "c4-storage-0-0", Namespace: fmNS,
			Labels: map[string]string{labelCluster: "c4", labelTier: tierStorage},
		},
	})
	r := fmBuild(t, objs...)

	res, err := r.reconcileFactorMigration(ctx, c)
	if err != nil {
		t.Fatalf("reconcileFactorMigration: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("expected a requeue while a storage pod still exists")
	}
	got := &garagev1beta2.GarageCluster{}
	_ = r.Get(ctx, types.NamespacedName{Name: "c4", Namespace: fmNS}, got)
	if got.Status.FactorMigration.Phase != fmPhaseScalingDown {
		t.Fatalf("expected to stay in ScalingDown while a pod exists, got %s", got.Status.FactorMigration.Phase)
	}
}

func TestFactorMigration_PurgePatchesInitContainerAndScalesUp(t *testing.T) {
	ctx := context.Background()
	c := fmCluster("c5")
	c.Status.FactorMigration = &garagev1beta2.FactorMigrationStatus{
		Phase: fmPhasePurging, ToFactor: 2, PurgeID: "p9", StartedAt: ptr.To(metav1.Now()),
	}
	objs := make([]client.Object, 0, 3)
	objs = append(objs, c, fmStorageNode("c5", 0, "ida"))
	objs = append(objs, &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: autoModeGarageNodeName("c5", 0), Namespace: fmNS},
		Spec: appsv1.StatefulSetSpec{
			Replicas: ptr.To(int32(0)),
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "garage"}}}},
		},
	})
	r := fmBuild(t, objs...)

	if _, err := r.reconcileFactorMigration(ctx, c); err != nil {
		t.Fatalf("reconcileFactorMigration: %v", err)
	}
	sts := &appsv1.StatefulSet{}
	_ = r.Get(ctx, types.NamespacedName{Name: autoModeGarageNodeName("c5", 0), Namespace: fmNS}, sts)
	if sts.Spec.Replicas == nil || *sts.Spec.Replicas != 1 {
		t.Fatal("STS should be scaled back to 1 during Purging")
	}
	foundInit := false
	for _, ic := range sts.Spec.Template.Spec.InitContainers {
		if ic.Name == fmPurgeInitContainerName {
			foundInit = true
			if !strings.Contains(ic.Command[2], "rm -f") || !strings.Contains(ic.Command[2], ".purged-p9") {
				t.Fatalf("init container script wrong: %q", ic.Command[2])
			}
		}
	}
	if !foundInit {
		t.Fatal("expected the purge init container to be patched in")
	}
	got := &garagev1beta2.GarageCluster{}
	_ = r.Get(ctx, types.NamespacedName{Name: "c5", Namespace: fmNS}, got)
	if got.Status.FactorMigration.Phase != fmPhaseVerifying {
		t.Fatalf("expected Verifying, got %s", got.Status.FactorMigration.Phase)
	}
}

func TestFactorMigration_AbortClearsSuspension(t *testing.T) {
	ctx := context.Background()
	c := fmCluster("c6", func(c *garagev1beta2.GarageCluster) {
		c.Annotations[garagev1beta1.AnnotationPurgeClusterLayout] = fmFactor2
		c.Annotations[garagev1beta1.AnnotationPurgeClusterLayoutAbort] = annotationTrue
	})
	c.Status.FactorMigration = &garagev1beta2.FactorMigrationStatus{Phase: fmPhaseScalingDown, PurgeID: "p1", StartedAt: ptr.To(metav1.Now())}
	n := fmStorageNode("c6", 0, "ida")
	n.Annotations = map[string]string{garagev1beta1.AnnotationOperatorSuspended: "p1"}
	r := fmBuild(t, c, n)

	if _, err := r.reconcileFactorMigration(ctx, c); err != nil {
		t.Fatalf("reconcileFactorMigration: %v", err)
	}
	got := &garagev1beta1.GarageNode{}
	_ = r.Get(ctx, types.NamespacedName{Name: autoModeGarageNodeName("c6", 0), Namespace: fmNS}, got)
	if _, ok := got.Annotations[garagev1beta1.AnnotationOperatorSuspended]; ok {
		t.Fatal("abort must clear the operator-suspended annotation")
	}
	gc := &garagev1beta2.GarageCluster{}
	_ = r.Get(ctx, types.NamespacedName{Name: "c6", Namespace: fmNS}, gc)
	if gc.Status.FactorMigration.Phase != fmPhaseFailed {
		t.Fatalf("expected Failed after abort, got %s", gc.Status.FactorMigration.Phase)
	}
	if _, ok := gc.Annotations[garagev1beta1.AnnotationPurgeClusterLayout]; ok {
		t.Fatal("abort must remove the purge annotation")
	}
}

func TestFactorMigration_BuildRebuildRoleChanges(t *testing.T) {
	ctx := context.Background()
	c := fmCluster("c7")
	storage := []client.Object{c}
	for i := 0; i < 2; i++ {
		storage = append(storage, fmStorageNode("c7", i, "sid"+string(rune('a'+i))))
	}
	// A gateway node with a known identity.
	gw := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "c7-gateway-0", Namespace: fmNS,
			Labels: map[string]string{labelCluster: "c7", labelTier: tierGateway, labelAppManagedBy: managedByOperatorValue},
		},
		Spec:   garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: "c7"}, Zone: "z", Gateway: true, Tags: []string{"tier:gateway"}},
		Status: garagev1beta1.GarageNodeStatus{NodeID: "gwid"},
	}
	storage = append(storage, gw)
	r := fmBuild(t, storage...)

	changes, err := r.buildRebuildRoleChanges(ctx, c)
	if err != nil {
		t.Fatalf("buildRebuildRoleChanges: %v", err)
	}
	if len(changes) != 3 {
		t.Fatalf("expected 3 role changes (2 storage + 1 gateway), got %d", len(changes))
	}
	storageRoles, gatewayRoles := 0, 0
	for _, ch := range changes {
		if ch.Capacity == nil {
			gatewayRoles++
		} else {
			storageRoles++
		}
	}
	if storageRoles != 2 || gatewayRoles != 1 {
		t.Fatalf("expected 2 storage + 1 gateway role, got %d storage %d gateway", storageRoles, gatewayRoles)
	}
}

func TestFactorMigration_PatchInitContainerIdempotent(t *testing.T) {
	ctx := context.Background()
	c := fmCluster("c8")
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: autoModeGarageNodeName("c8", 0), Namespace: fmNS},
		Spec: appsv1.StatefulSetSpec{
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "garage"}}}},
		},
	}
	r := fmBuild(t, c, sts)
	name := autoModeGarageNodeName("c8", 0)

	// Add twice — must not duplicate.
	if err := r.patchSTSPurgeInitContainer(ctx, c, name, "p1", true); err != nil {
		t.Fatal(err)
	}
	if err := r.patchSTSPurgeInitContainer(ctx, c, name, "p1", true); err != nil {
		t.Fatal(err)
	}
	got := &appsv1.StatefulSet{}
	_ = r.Get(ctx, types.NamespacedName{Name: name, Namespace: fmNS}, got)
	count := 0
	for _, ic := range got.Spec.Template.Spec.InitContainers {
		if ic.Name == fmPurgeInitContainerName {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 purge init container, got %d", count)
	}
	// Remove — must be gone.
	if err := r.patchSTSPurgeInitContainer(ctx, c, name, "", false); err != nil {
		t.Fatal(err)
	}
	got = &appsv1.StatefulSet{}
	_ = r.Get(ctx, types.NamespacedName{Name: name, Namespace: fmNS}, got)
	for _, ic := range got.Spec.Template.Spec.InitContainers {
		if ic.Name == fmPurgeInitContainerName {
			t.Fatal("purge init container should be removed")
		}
	}
}
