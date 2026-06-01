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
	"sort"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
)

// test namespace names used across the reference-grant table tests
const (
	nsApp     = "app"
	nsStorage = "storage"
	nsData    = "data"
)

func TestGrantTargetNamespaces(t *testing.T) {
	tests := []struct {
		name string
		obj  client.Object
		want []string
	}{
		{
			name: "key with cross-ns cluster and bucket refs",
			obj: &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: nsApp},
				Spec: garagev1beta1.GarageKeySpec{
					ClusterRef: garagev1beta1.ClusterReference{Namespace: nsStorage},
					BucketPermissions: []garagev1beta1.BucketPermission{
						{BucketRef: &garagev1beta1.BucketRef{Name: "b", Namespace: nsData}},
					},
				},
			},
			want: []string{nsData, nsStorage},
		},
		{
			name: "key with same-ns refs only",
			obj: &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: nsApp},
				Spec: garagev1beta1.GarageKeySpec{
					ClusterRef: garagev1beta1.ClusterReference{Namespace: ""},
				},
			},
			want: nil,
		},
		{
			name: "bucket with cross-ns cluster ref",
			obj: &garagev1beta1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: nsApp},
				Spec: garagev1beta1.GarageBucketSpec{
					ClusterRef: garagev1beta1.ClusterReference{Namespace: nsStorage},
				},
			},
			want: []string{nsStorage},
		},
		{
			name: "admin token with explicit same-ns cluster ref",
			obj: &garagev1beta1.GarageAdminToken{
				ObjectMeta: metav1.ObjectMeta{Name: "t", Namespace: nsApp},
				Spec: garagev1beta1.GarageAdminTokenSpec{
					ClusterRef: garagev1beta1.ClusterReference{Namespace: nsApp},
				},
			},
			want: nil,
		},
		{
			name: "key with two bucket refs into same ns dedups",
			obj: &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: nsApp},
				Spec: garagev1beta1.GarageKeySpec{
					BucketPermissions: []garagev1beta1.BucketPermission{
						{BucketRef: &garagev1beta1.BucketRef{Name: "b1", Namespace: nsData}},
						{BucketRef: &garagev1beta1.BucketRef{Name: "b2", Namespace: nsData}},
					},
				},
			},
			want: []string{nsData},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := grantTargetNamespaces(tt.obj)
			sort.Strings(got)
			want := append([]string(nil), tt.want...)
			sort.Strings(want)
			if len(got) != len(want) {
				t.Fatalf("grantTargetNamespaces = %v, want %v", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("grantTargetNamespaces = %v, want %v", got, want)
				}
			}
		})
	}
}

func TestMapToGrantsScoped(t *testing.T) {
	s := fmScheme(t)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(
		&garagev1beta1.GarageReferenceGrant{
			ObjectMeta: metav1.ObjectMeta{Name: "g-storage", Namespace: nsStorage},
		},
		&garagev1beta1.GarageReferenceGrant{
			ObjectMeta: metav1.ObjectMeta{Name: "g-other", Namespace: "other"},
		},
	).Build()

	// Mirror the SetupWithManager mapToGrants closure against the fake client.
	mapToGrants := func(ctx context.Context, obj client.Object) []reconcile.Request {
		var reqs []reconcile.Request
		seen := map[string]bool{}
		for _, ns := range grantTargetNamespaces(obj) {
			var grants garagev1beta1.GarageReferenceGrantList
			if err := c.List(ctx, &grants, client.InNamespace(ns)); err != nil {
				continue
			}
			for _, g := range grants.Items {
				key := g.Namespace + "/" + g.Name
				if seen[key] {
					continue
				}
				seen[key] = true
				reqs = append(reqs, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: g.Name, Namespace: g.Namespace},
				})
			}
		}
		return reqs
	}

	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: nsApp},
		Spec: garagev1beta1.GarageKeySpec{
			ClusterRef: garagev1beta1.ClusterReference{Namespace: nsStorage},
		},
	}

	reqs := mapToGrants(context.Background(), key)
	if len(reqs) != 1 {
		t.Fatalf("mapToGrants returned %d requests, want 1: %v", len(reqs), reqs)
	}
	want := reconcile.Request{NamespacedName: types.NamespacedName{Name: "g-storage", Namespace: nsStorage}}
	if reqs[0] != want {
		t.Fatalf("mapToGrants = %v, want %v (g-other in unrelated ns must not be enqueued)", reqs[0], want)
	}
}
