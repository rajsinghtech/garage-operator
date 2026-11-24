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
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// Issue #588: a cross-namespace GarageCluster grant must not let the granted
// namespace reach every bucket unless the grant opts into bucketScope: Cluster.

const (
	scopeClusterNS = "garage-system"
	scopeTenantNS  = "tenant-a"
	scopeOtherNS   = "tenant-b"
	scopeCluster   = "garage"
)

// scopeGrant builds a cluster-namespace grant. scope "" leaves bucketScope
// unset; omitTo drops the To list entirely (the legacy wildcard form).
func scopeGrant(name, fromKind, fromNS string, scope GrantBucketScope, omitTo bool) *GarageReferenceGrant {
	g := &GarageReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: scopeClusterNS},
		Spec: GarageReferenceGrantSpec{
			From: []ReferenceGrantFrom{{Kind: fromKind, Namespace: fromNS}},
		},
	}
	if !omitTo {
		g.Spec.To = []ReferenceGrantTo{{Kind: garageClusterKind, Name: scopeCluster, BucketScope: scope}}
	}
	return g
}

func TestResolveClusterGrantScope(t *testing.T) {
	selectorCluster := scopeGrant("selector", garageKeyKind, "", GrantBucketScopeCluster, false)
	selectorCluster.Spec.From = []ReferenceGrantFrom{{Kind: garageKeyKind, NamespaceSelector: &metav1.LabelSelector{
		MatchLabels: map[string]string{"tenant": "trusted"},
	}}}
	otherCluster := scopeGrant("other-cluster", garageKeyKind, scopeTenantNS, GrantBucketScopeCluster, false)
	otherCluster.Spec.To[0].Name = "another-cluster"
	tenantNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: scopeTenantNS, Labels: map[string]string{"tenant": "trusted"}}}

	cases := []struct {
		name       string
		fromNS     string
		objects    []client.Object
		want       GrantBucketScope
		wantDenied bool
	}{
		{name: "same namespace is cluster-wide", fromNS: scopeClusterNS, want: GrantBucketScopeCluster},
		{name: "no grant is denied and referenced", fromNS: scopeTenantNS, want: GrantBucketScopeReferenced, wantDenied: true},
		{name: "omitted To defaults to Referenced", fromNS: scopeTenantNS,
			objects: []client.Object{scopeGrant("g", garageKeyKind, scopeTenantNS, "", true)}, want: GrantBucketScopeReferenced},
		{name: "unset bucketScope defaults to Referenced", fromNS: scopeTenantNS,
			objects: []client.Object{scopeGrant("g", garageKeyKind, scopeTenantNS, "", false)}, want: GrantBucketScopeReferenced},
		{name: "explicit Referenced", fromNS: scopeTenantNS,
			objects: []client.Object{scopeGrant("g", garageKeyKind, scopeTenantNS, GrantBucketScopeReferenced, false)}, want: GrantBucketScopeReferenced},
		{name: "explicit Cluster", fromNS: scopeTenantNS,
			objects: []client.Object{scopeGrant("g", garageKeyKind, scopeTenantNS, GrantBucketScopeCluster, false)}, want: GrantBucketScopeCluster},
		{name: "Cluster for another cluster name does not apply", fromNS: scopeTenantNS,
			objects: []client.Object{otherCluster, scopeGrant("g", garageKeyKind, scopeTenantNS, "", false)}, want: GrantBucketScopeReferenced},
		{name: "Cluster for another kind does not apply", fromNS: scopeTenantNS,
			objects: []client.Object{scopeGrant("g", garageBucketKind, scopeTenantNS, GrantBucketScopeCluster, false),
				scopeGrant("k", garageKeyKind, scopeTenantNS, "", false)}, want: GrantBucketScopeReferenced},
		{name: "widest matching grant wins", fromNS: scopeTenantNS,
			objects: []client.Object{scopeGrant("narrow", garageKeyKind, scopeTenantNS, "", false),
				scopeGrant("wide", garageKeyKind, scopeTenantNS, GrantBucketScopeCluster, false)}, want: GrantBucketScopeCluster},
		{name: "selector grant can widen an exact grant", fromNS: scopeTenantNS,
			objects: []client.Object{tenantNamespace, scopeGrant("exact", garageKeyKind, scopeTenantNS, "", false), selectorCluster},
			want:    GrantBucketScopeCluster},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(tc.objects...).Build()
			got, err := ResolveClusterGrantScope(t.Context(), c, garageKeyKind, tc.fromNS, scopeClusterNS, scopeCluster)
			if tc.wantDenied {
				if !IsReferenceGrantDenied(err) {
					t.Fatalf("err = %v, want reference grant denial", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("scope = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReferenceGrantValidator_BucketScope(t *testing.T) {
	v := &GarageReferenceGrantValidator{}
	g := scopeGrant("g", garageKeyKind, scopeTenantNS, GrantBucketScopeCluster, false)
	warnings, err := v.ValidateCreate(t.Context(), g)
	if err != nil {
		t.Fatalf("Cluster scope rejected: %v", err)
	}
	if len(warnings) == 0 || !strings.Contains(strings.Join(warnings, " "), "every bucket") {
		t.Fatalf("warnings = %v, want a cluster-wide reach warning", warnings)
	}
	bad := scopeGrant("g", garageKeyKind, scopeTenantNS, GrantBucketScopeCluster, false)
	bad.Spec.To[0].Kind = garageBucketKind
	if _, err := v.ValidateCreate(t.Context(), bad); err == nil {
		t.Fatal("bucketScope on a GarageBucket target was accepted")
	}
}

func scopeKey(perms []BucketPermission, all *AllBucketsPermission) *GarageKey {
	return &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: scopeTenantNS},
		Spec: GarageKeySpec{
			ClusterRef:        ClusterReference{Name: scopeCluster, Namespace: scopeClusterNS},
			BucketPermissions: perms,
			AllBuckets:        all,
		},
	}
}

func scopeBucket(name, namespace, bucketID string) *GarageBucket {
	return &GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       GarageBucketSpec{ClusterRef: ClusterReference{Name: scopeCluster, Namespace: scopeClusterNS}},
		Status:     GarageBucketStatus{BucketID: bucketID},
	}
}

func TestGarageKeyValidator_BucketScope(t *testing.T) {
	own := scopeBucket("own", scopeTenantNS, "id-own")
	foreign := scopeBucket("foreign", scopeOtherNS, "id-foreign")
	sharedBucketGrant := &GarageReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "share", Namespace: scopeOtherNS},
		Spec: GarageReferenceGrantSpec{
			From: []ReferenceGrantFrom{{Kind: garageKeyKind, Namespace: scopeTenantNS}},
			To:   []ReferenceGrantTo{{Kind: garageBucketKind, Name: "foreign"}},
		},
	}
	readAll := &AllBucketsPermission{Read: true}

	cases := []struct {
		name        string
		scope       GrantBucketScope
		extra       []client.Object
		key         *GarageKey
		wantErr     bool
		wantWarning string
	}{
		{name: "allBuckets denied with unset scope", key: scopeKey(nil, readAll), wantErr: true},
		{name: "allBuckets denied with Referenced", scope: GrantBucketScopeReferenced, key: scopeKey(nil, readAll), wantErr: true},
		{name: "allBuckets allowed with Cluster", scope: GrantBucketScopeCluster, key: scopeKey(nil, readAll)},
		{name: "bucketId of own GarageBucket allowed", key: scopeKey([]BucketPermission{{BucketID: "id-own", Read: true}}, nil)},
		{name: "globalAlias of own GarageBucket allowed", key: scopeKey([]BucketPermission{{GlobalAlias: "own", Read: true}}, nil)},
		{name: "bucketId of foreign GarageBucket denied", key: scopeKey([]BucketPermission{{BucketID: "id-foreign", Read: true}}, nil), wantErr: true},
		{name: "globalAlias of foreign GarageBucket denied", key: scopeKey([]BucketPermission{{GlobalAlias: "foreign", Read: true}}, nil), wantErr: true},
		{name: "bucketId of granted foreign GarageBucket allowed", extra: []client.Object{sharedBucketGrant},
			key: scopeKey([]BucketPermission{{BucketID: "id-foreign", Read: true}}, nil)},
		{name: "bucketId of foreign GarageBucket allowed with Cluster", scope: GrantBucketScopeCluster,
			key: scopeKey([]BucketPermission{{BucketID: "id-foreign", Read: true}}, nil)},
		{name: "unmanaged bucketId warns", key: scopeKey([]BucketPermission{{BucketID: "id-unmanaged", Read: true}}, nil),
			wantWarning: "does not match a GarageBucket"},
		{name: "unmanaged globalAlias warns", key: scopeKey([]BucketPermission{{GlobalAlias: "unmanaged", Read: true}}, nil),
			wantWarning: "does not match a GarageBucket"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objects := append([]client.Object{scopeGrant("g", garageKeyKind, scopeTenantNS, tc.scope, false), own, foreign}, tc.extra...)
			c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).WithObjects(objects...).Build()
			v := &GarageKeyValidator{Client: c}
			warnings, err := v.ValidateCreate(t.Context(), tc.key)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "bucketScope Referenced") {
					t.Fatalf("err = %v, want bucketScope denial", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantWarning != "" && !strings.Contains(strings.Join(warnings, " "), tc.wantWarning) {
				t.Fatalf("warnings = %v, want %q", warnings, tc.wantWarning)
			}
		})
	}

	t.Run("same namespace allBuckets unaffected", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
		key := scopeKey(nil, readAll)
		key.Namespace = scopeClusterNS
		if _, err := (&GarageKeyValidator{Client: c}).ValidateCreate(t.Context(), key); err != nil {
			t.Fatalf("same-namespace allBuckets rejected: %v", err)
		}
	})
}

func TestGarageBucketValidator_BucketScopeAdoption(t *testing.T) {
	adopting := func() *GarageBucket {
		b := scopeBucket("adopt", scopeTenantNS, "")
		b.Spec.BucketID = "id-unmanaged"
		return b
	}
	for _, tc := range []struct {
		name    string
		scope   GrantBucketScope
		wantErr bool
	}{
		{name: "unset scope denies adoption", wantErr: true},
		{name: "Referenced denies adoption", scope: GrantBucketScopeReferenced, wantErr: true},
		{name: "Cluster allows adoption", scope: GrantBucketScopeCluster},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).
				WithObjects(scopeGrant("g", garageBucketKind, scopeTenantNS, tc.scope, false)).Build()
			_, err := (&GarageBucketValidator{Client: c}).ValidateCreate(t.Context(), adopting())
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "bucketScope Referenced") {
				t.Fatalf("err = %v, want bucketScope message", err)
			}
		})
	}

	t.Run("same namespace adoption unaffected", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()
		b := adopting()
		b.Namespace = scopeClusterNS
		if _, err := (&GarageBucketValidator{Client: c}).ValidateCreate(t.Context(), b); err != nil {
			t.Fatalf("same-namespace adoption rejected: %v", err)
		}
	})

	t.Run("legacy adoption stays editable with a warning but cannot drop spec.bucketId", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(fakeScheme(t)).
			WithObjects(scopeGrant("g", garageBucketKind, scopeTenantNS, "", false)).Build()
		v := &GarageBucketValidator{Client: c}
		oldObj := adopting()
		oldObj.Status.BucketID = oldObj.Spec.BucketID
		edited := oldObj.DeepCopy()
		edited.Spec.DeletionPolicy = BucketDeletionPolicyRetain
		warnings, err := v.ValidateUpdate(t.Context(), oldObj, edited)
		if err != nil {
			t.Fatalf("unchanged legacy adoption edit rejected: %v", err)
		}
		if !strings.Contains(strings.Join(warnings, " "), "no longer manages") {
			t.Fatalf("warnings = %v, want fenced-adoption warning", warnings)
		}
		dropped := oldObj.DeepCopy()
		dropped.Spec.BucketID = ""
		if _, err := v.ValidateUpdate(t.Context(), oldObj, dropped); err == nil {
			t.Fatal("removing spec.bucketId laundered an out-of-scope adoption into status")
		}
	})
}

// TestGarageReferenceGrantCRDBucketScopeSchema pins the CRD contract of
// spec.to[].bucketScope (#588) in the kustomize and Helm copies: the enum, no
// default (unset must stay distinguishable and mean Referenced), and the CEL
// rule limiting it to GarageCluster targets.
func TestGarageReferenceGrantCRDBucketScopeSchema(t *testing.T) {
	const rule = "!has(self.bucketScope) || self.kind == 'GarageCluster'"
	for _, root := range []string{
		filepath.Join("..", "..", "config", "crd", "bases"),
		filepath.Join("..", "..", "charts", "garage-operator", "crd-bases"),
	} {
		t.Run(filepath.Base(root), func(t *testing.T) {
			version := clusterCRDVersion(t, filepath.Join(root, "garage.rajsingh.info_garagereferencegrants.yaml"), "v1beta1")
			to := version.Schema.OpenAPIV3Schema.Properties["spec"].Properties["to"].Items.Schema
			scope, ok := to.Properties["bucketScope"]
			if !ok {
				t.Fatal("spec.to[].bucketScope missing")
			}
			if scope.Default != nil {
				t.Fatalf("bucketScope must have no CRD default, got %s", string(scope.Default.Raw))
			}
			var enum []string
			for _, value := range scope.Enum {
				enum = append(enum, string(value.Raw))
			}
			if want := []string{`"Referenced"`, `"Cluster"`}; !reflect.DeepEqual(enum, want) {
				t.Fatalf("bucketScope enum = %v, want %v", enum, want)
			}
			found := false
			for _, validation := range to.XValidations {
				if validation.Rule == rule {
					found = true
				}
			}
			if !found {
				t.Fatalf("spec.to[] validations = %+v, want %q", to.XValidations, rule)
			}
		})
	}
}
