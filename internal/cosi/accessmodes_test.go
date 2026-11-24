/*
Copyright 2026.

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

package cosi

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	ctrlutil "sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	cosiv1alpha2 "sigs.k8s.io/container-object-storage-interface/client/apis/objectstorage/v1alpha2"
)

func TestMapAccessModesFromAPI(t *testing.T) {
	const (
		rw = cosiv1alpha2.BucketAccessModeReadWrite
		ro = cosiv1alpha2.BucketAccessModeReadOnly
		wo = cosiv1alpha2.BucketAccessModeWriteOnly
	)
	cases := []struct {
		name string
		in   cosiv1alpha2.BucketAccessModes
		want AccessMode
	}{
		{"both unset keeps the ReadWrite default", cosiv1alpha2.BucketAccessModes{}, AccessModeReadWrite},
		{"objectData ReadWrite", cosiv1alpha2.BucketAccessModes{ObjectData: rw}, AccessModeReadWrite},
		{"objectData ReadOnly", cosiv1alpha2.BucketAccessModes{ObjectData: ro}, AccessModeReadOnly},
		{"objectData WriteOnly", cosiv1alpha2.BucketAccessModes{ObjectData: wo}, AccessModeWriteOnly},
		{"objectMetadata alone ReadOnly", cosiv1alpha2.BucketAccessModes{ObjectMetadata: ro}, AccessModeReadOnly},
		{"read data + write metadata unions to ReadWrite", cosiv1alpha2.BucketAccessModes{ObjectData: ro, ObjectMetadata: wo}, AccessModeReadWrite},
		{"both ReadOnly", cosiv1alpha2.BucketAccessModes{ObjectData: ro, ObjectMetadata: ro}, AccessModeReadOnly},
		{"bucketMetadata alone does not widen the default", cosiv1alpha2.BucketAccessModes{BucketMetadata: ro}, AccessModeReadWrite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapAccessModesFromAPI(tc.in); got != tc.want {
				t.Fatalf("mapAccessModesFromAPI(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// legacyReader serves one BucketAccess as the legacy COSI CRD stores it, with
// the singular spec.bucketClaims[].accessMode the typed client drops.
type legacyReader struct {
	client.Reader
	obj map[string]any
}

func (l legacyReader) Get(_ context.Context, _ client.ObjectKey, out client.Object, _ ...client.GetOption) error {
	out.(*unstructured.Unstructured).Object = l.obj
	return nil
}

func legacyAccess(modes ...string) (*cosiv1alpha2.BucketAccess, map[string]any) {
	access := &cosiv1alpha2.BucketAccess{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns"}}
	claims := make([]any, 0, len(modes))
	for i, m := range modes {
		name := fmt.Sprintf("claim-%d", i)
		access.Spec.BucketClaims = append(access.Spec.BucketClaims, cosiv1alpha2.BucketClaimAccess{BucketClaimName: name})
		claim := map[string]any{"bucketClaimName": name}
		if m != "" {
			claim["accessMode"] = m
		}
		claims = append(claims, claim)
	}
	return access, map[string]any{"spec": map[string]any{"bucketClaims": claims}}
}

func TestLegacyAccessModeKeepsReadOnlyAndWriteOnly(t *testing.T) {
	access, raw := legacyAccess("ReadOnly", "WriteOnly", "ReadWrite")
	r := &BucketAccessReconciler{APIReader: legacyReader{obj: raw}}
	modes, err := r.legacyAccessModes(t.Context(), access)
	if err != nil {
		t.Fatal(err)
	}
	want := []AccessMode{AccessModeReadOnly, AccessModeWriteOnly, AccessModeReadWrite}
	for i, bca := range access.Spec.BucketClaims {
		if got := accessModeForClaim(bca, i, modes); got != want[i] {
			t.Fatalf("claim %d: got %v, want %v", i, got, want[i])
		}
	}
}

func TestLegacyAccessModeFailsClosedWithoutEitherField(t *testing.T) {
	access, raw := legacyAccess("ReadOnly", "")
	r := &BucketAccessReconciler{APIReader: legacyReader{obj: raw}}
	if _, err := r.legacyAccessModes(t.Context(), access); err == nil {
		t.Fatal("a claim with neither accessModes nor accessMode must not default to ReadWrite")
	}
}

func TestAccessModesWinOverLegacyField(t *testing.T) {
	bca := cosiv1alpha2.BucketClaimAccess{AccessModes: cosiv1alpha2.BucketAccessModes{ObjectData: cosiv1alpha2.BucketAccessModeReadOnly}}
	if got := accessModeForClaim(bca, 0, []cosiv1alpha2.BucketAccessMode{cosiv1alpha2.BucketAccessModeReadWrite}); got != AccessModeReadOnly {
		t.Fatalf("got %v, want ReadOnly", got)
	}
}

// TestFinalizerWriteIsMetadataOnly pins that finalizer writes never send the
// spec: a full Update would strip whichever access field the installed COSI
// CRD generation has and the typed client does not.
func TestFinalizerWriteIsMetadataOnly(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := cosiv1alpha2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	access := &cosiv1alpha2.BucketAccess{
		ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns"},
		Spec: cosiv1alpha2.BucketAccessSpec{BucketClaims: []cosiv1alpha2.BucketClaimAccess{{
			BucketClaimName: "c", AccessSecretName: "s",
			AccessModes: cosiv1alpha2.BucketAccessModes{ObjectData: cosiv1alpha2.BucketAccessModeReadOnly},
		}}},
	}
	var patches [][]byte
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(access).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
				t.Fatal("finalizer writes must not use Update")
				return nil
			},
			Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				data, err := patch.Data(obj)
				if err != nil {
					return err
				}
				patches = append(patches, data)
				return c.Patch(ctx, obj, patch, opts...)
			},
		}).Build()
	r := &BucketAccessReconciler{Client: kubeClient}
	got := &cosiv1alpha2.BucketAccess{}
	if err := kubeClient.Get(t.Context(), client.ObjectKeyFromObject(access), got); err != nil {
		t.Fatal(err)
	}
	if err := r.patchMetadata(t.Context(), got, func(a *cosiv1alpha2.BucketAccess) {
		ctrlutil.AddFinalizer(a, GarageProtectionFinalizer)
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.patchMetadata(t.Context(), got, r.completeCleanupHandoff); err != nil {
		t.Fatal(err)
	}
	if len(patches) != 2 {
		t.Fatalf("got %d patches, want 2", len(patches))
	}
	for _, data := range patches {
		var body map[string]any
		if err := json.Unmarshal(data, &body); err != nil {
			t.Fatal(err)
		}
		for key := range body {
			if key != "metadata" {
				t.Fatalf("patch %s touches %q, want metadata only", data, key)
			}
		}
	}
}
