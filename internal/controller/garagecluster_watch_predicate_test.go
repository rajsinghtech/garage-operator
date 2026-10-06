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
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func predicateTestCluster() *garagev1beta2.GarageCluster {
	return &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "garage", Namespace: "garage", Generation: 3, ResourceVersion: "10",
			Labels:      map[string]string{"app": "garage"},
			Annotations: map[string]string{"note": "x"},
			Finalizers:  []string{garageClusterFinalizer},
		},
		Status: garagev1beta2.GarageClusterStatus{
			Phase: "Running",
			StorageDrain: &garagev1beta2.StorageDrainStatus{
				TransactionID: "tx-1", TargetHash: "h1", QueueLength: 5, ErrorCount: 1,
			},
		},
	}
}

func TestGarageClusterPrimaryPredicateUpdates(t *testing.T) {
	t.Parallel()
	now := metav1.NewTime(time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC))
	cases := []struct {
		name   string
		mutate func(*garagev1beta2.GarageCluster)
		want   bool
	}{
		{"resourceVersion only", func(c *garagev1beta2.GarageCluster) { c.ResourceVersion = "11" }, false},
		{"live status projections", func(c *garagev1beta2.GarageCluster) {
			c.Status.StorageStats = &garagev1beta2.ClusterStorageStats{UsedCapacity: resource.NewQuantity(1, resource.BinarySI)}
			c.Status.ResyncQueueLength = ptr.To[int64](700)
			c.Status.BlockErrors = ptr.To[int32](2)
			c.Status.Health = &garagev1beta2.ClusterHealth{Status: "degraded"}
			c.Status.Phase = "Degraded"
			c.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionFalse}}
		}, false},
		{"drain diagnostic counters", func(c *garagev1beta2.GarageCluster) {
			c.Status.StorageDrain.QueueLength = 9
			c.Status.StorageDrain.ErrorCount = 0
		}, false},
		{"generation", func(c *garagev1beta2.GarageCluster) { c.Generation++ }, true},
		{"operation annotation", func(c *garagev1beta2.GarageCluster) {
			c.Annotations["garage.rajsingh.info/connect-nodes"] = "true"
		}, true},
		{"annotation removed", func(c *garagev1beta2.GarageCluster) { delete(c.Annotations, "note") }, true},
		{"label", func(c *garagev1beta2.GarageCluster) { c.Labels["tier"] = "edge" }, true},
		{"finalizer", func(c *garagev1beta2.GarageCluster) { c.Finalizers = nil }, true},
		{"deletion started", func(c *garagev1beta2.GarageCluster) { c.DeletionTimestamp = &now }, true},
		{"drain proof evidence", func(c *garagev1beta2.GarageCluster) { c.Status.StorageDrain.QuietSince = &now }, true},
		{"drain released by another controller", func(c *garagev1beta2.GarageCluster) { c.Status.StorageDrain = nil }, true},
		{"rollout actor transferred", func(c *garagev1beta2.GarageCluster) {
			c.Status.StorageRollout = &garagev1beta2.StorageRolloutStatus{GarageNodeName: "garage-0"}
		}, true},
	}
	p := garageClusterPrimaryPredicate()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			oldCluster := predicateTestCluster()
			newCluster := oldCluster.DeepCopy()
			tc.mutate(newCluster)
			if got := p.Update(event.UpdateEvent{ObjectOld: oldCluster, ObjectNew: newCluster}); got != tc.want {
				t.Fatalf("Update() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestGarageClusterPrimaryPredicatePassesLifecycleEvents(t *testing.T) {
	t.Parallel()
	p := garageClusterPrimaryPredicate()
	cluster := predicateTestCluster()
	if !p.Create(event.CreateEvent{Object: cluster}) || !p.Delete(event.DeleteEvent{Object: cluster}) ||
		!p.Generic(event.GenericEvent{Object: cluster}) {
		t.Fatal("create, delete and generic events must always reach Reconcile")
	}
}

func TestRequeueSuccessfulGarageClusterResult(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := metav1.Now()
	live := predicateTestCluster()
	live.ResourceVersion = ""
	deleting := predicateTestCluster()
	deleting.Name, deleting.ResourceVersion, deleting.DeletionTimestamp = "deleting", "", &now
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(live, deleting).Build()
	r := &GarageClusterReconciler{Client: kubeClient}
	ctx := context.Background()
	request := func(name string) ctrl.Request {
		return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "garage", Name: name}}
	}

	res, err := r.requeueSuccessfulGarageClusterResult(ctx, request("garage"), ctrl.Result{}, nil)
	if err != nil || res.RequeueAfter != RequeueAfterError {
		t.Fatalf("live cluster with an empty result: got %+v, %v; want RequeueAfter=%s", res, err, RequeueAfterError)
	}
	explicit := ctrl.Result{RequeueAfter: time.Nanosecond}
	if res, _ := r.requeueSuccessfulGarageClusterResult(ctx, request("garage"), explicit, nil); res != explicit {
		t.Fatalf("explicit result was rewritten to %+v", res)
	}
	if res, err := r.requeueSuccessfulGarageClusterResult(ctx, request("garage"), ctrl.Result{}, context.Canceled); err == nil || !res.IsZero() {
		t.Fatalf("error result must pass through unchanged, got %+v, %v", res, err)
	}
	if res, _ := r.requeueSuccessfulGarageClusterResult(ctx, request("deleting"), ctrl.Result{}, nil); !res.IsZero() {
		t.Fatalf("deleting cluster must not be requeued by the safety net, got %+v", res)
	}
	if res, _ := r.requeueSuccessfulGarageClusterResult(ctx, request("gone"), ctrl.Result{}, nil); !res.IsZero() {
		t.Fatalf("deleted cluster must not be requeued, got %+v", res)
	}
}
