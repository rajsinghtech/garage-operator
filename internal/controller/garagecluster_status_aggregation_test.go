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
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func garageClusterStatusTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("add apps/v1 scheme: %v", err)
	}
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatalf("add v1beta1 scheme: %v", err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatalf("add v1beta2 scheme: %v", err)
	}
	return scheme
}

func newZeroReplicaGarageCluster(name string) *garagev1beta2.GarageCluster {
	return &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "status-test"},
	}
}

func TestGarageClusterStatusListFailureDoesNotPublishCompleteAggregation(t *testing.T) {
	scheme := garageClusterStatusTestScheme(t)
	cluster := newZeroReplicaGarageCluster("list-failure")
	base := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		WithObjects(cluster).
		Build()

	listErr := errors.New("synthetic GarageNode list failure")
	kubeClient := interceptor.NewClient(base, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*garagev1beta1.GarageNodeList); ok {
				return listErr
			}
			return c.List(ctx, list, opts...)
		},
	})

	current := &garagev1beta2.GarageCluster{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(cluster), current); err != nil {
		t.Fatalf("get cluster: %v", err)
	}

	result, err := (&GarageClusterReconciler{Client: kubeClient, Scheme: scheme}).updateStatusFromCluster(context.Background(), current)
	if err != nil {
		t.Fatalf("updateStatusFromCluster returned error: %v", err)
	}
	if result.RequeueAfter != RequeueAfterError {
		t.Fatalf("requeue delay = %s, want %s", result.RequeueAfter, RequeueAfterError)
	}

	updated := &garagev1beta2.GarageCluster{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(cluster), updated); err != nil {
		t.Fatalf("get updated cluster: %v", err)
	}
	if updated.Status.Phase != "Unknown" {
		t.Fatalf("phase = %q, want Unknown after an incomplete node list", updated.Status.Phase)
	}
	ready := meta.FindStatusCondition(updated.Status.Conditions, PhaseReady)
	if ready == nil || ready.Status != metav1.ConditionFalse {
		t.Fatalf("Ready condition = %#v, want False after an incomplete node list", ready)
	}
	if !strings.Contains(ready.Message, listErr.Error()) {
		t.Fatalf("Ready condition message = %q, want list failure", ready.Message)
	}
}

func TestGarageClusterStatusEmptyNodeListRemainsNormal(t *testing.T) {
	scheme := garageClusterStatusTestScheme(t)
	cluster := newZeroReplicaGarageCluster("empty-list")
	base := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		WithObjects(cluster).
		Build()

	current := &garagev1beta2.GarageCluster{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(cluster), current); err != nil {
		t.Fatalf("get cluster: %v", err)
	}

	result, err := (&GarageClusterReconciler{Client: base, Scheme: scheme}).updateStatusFromCluster(context.Background(), current)
	if err != nil {
		t.Fatalf("updateStatusFromCluster returned error: %v", err)
	}
	if result.RequeueAfter != RequeueAfterLong {
		t.Fatalf("requeue delay = %s, want %s", result.RequeueAfter, RequeueAfterLong)
	}

	updated := &garagev1beta2.GarageCluster{}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(cluster), updated); err != nil {
		t.Fatalf("get updated cluster: %v", err)
	}
	if updated.Status.Phase != PhasePending {
		t.Fatalf("phase = %q, want %s for a successful empty node list", updated.Status.Phase, PhasePending)
	}
	if ready := meta.FindStatusCondition(updated.Status.Conditions, PhaseReady); ready != nil && ready.Status == metav1.ConditionFalse {
		t.Fatalf("Ready condition = %#v, want no degraded failure for an empty node list", ready)
	}
}
