package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// A bucketRef whose GarageBucket was deleted (or is not created yet) must not
// block the key's other grants, and must not revoke a grant it may own.
func TestReconcileManagedBucketPermissions_PendingBucketRefDoesNotBlockOtherGrants(t *testing.T) {
	const (
		keyID       = "GKpendingref"
		oldBucketID = "bucket-from-deleted-ref"
		newBucketID = "bucket-new-grant"
	)
	s := runtime.NewScheme()
	_ = garagev1beta1.AddToScheme(s)
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: testNamespace, Generation: 2},
		Spec: garagev1beta1.GarageKeySpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: testClusterName},
			BucketPermissions: []garagev1beta1.BucketPermission{
				{BucketRef: &garagev1beta1.BucketRef{Name: "deleted-bucket"}, Read: true},
				{BucketID: newBucketID, Write: true},
			},
		},
		Status: garagev1beta1.GarageKeyStatus{AccessKeyID: keyID, ManagedBucketGrants: []string{oldBucketID}},
	}
	fc := fake.NewClientBuilder().WithScheme(s).WithObjects(key).
		WithStatusSubresource(&garagev1beta1.GarageKey{}).Build()
	r := &GarageKeyReconciler{Client: fc, Scheme: s}
	var allows []garage.AllowBucketKeyRequest
	var denies []garage.DenyBucketKeyRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/v2/AllowBucketKey":
			var body garage.AllowBucketKeyRequest
			_ = json.NewDecoder(req.Body).Decode(&body)
			allows = append(allows, body)
		case "/v2/DenyBucketKey":
			var body garage.DenyBucketKeyRequest
			_ = json.NewDecoder(req.Body).Decode(&body)
			denies = append(denies, body)
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	existing := &garage.Key{AccessKeyID: keyID, Buckets: []garage.KeyBucket{{
		ID: oldBucketID, Permissions: garage.BucketKeyPerms{Read: true},
	}}}
	err := r.reconcileManagedBucketPermissions(context.Background(), key, garage.NewClient(srv.URL, "tok"), existing)
	if err == nil || !strings.Contains(err.Error(), "waiting for bucket deleted-bucket") {
		t.Fatalf("err=%v, want the pending bucketRef reported", err)
	}
	if len(allows) != 1 || allows[0].BucketID != newBucketID || !allows[0].Permissions.Write {
		t.Fatalf("allows=%+v, want Write granted on %s despite the pending ref", allows, newBucketID)
	}
	if len(denies) != 0 {
		t.Fatalf("denies=%+v, want no revocation while a ref is unresolved", denies)
	}
	if !stringSliceContains(key.Status.ManagedBucketGrants, oldBucketID) {
		t.Fatalf("managed grants=%v, want %s still reserved", key.Status.ManagedBucketGrants, oldBucketID)
	}
	cond := meta.FindStatusCondition(key.Status.Conditions, garagev1beta1.ConditionPermissionsConfigured)
	if cond == nil || cond.Status != metav1.ConditionFalse || !strings.Contains(cond.Message, "deleted-bucket") {
		t.Fatalf("PermissionsConfigured=%+v, want False naming the pending ref", cond)
	}
}

func TestHoldManagedGrantsWhileUnresolved(t *testing.T) {
	desired := map[string]garage.BucketKeyPerms{"a": {Read: true}}
	targets := map[string]struct{}{"a": {}, "b": {}, "denied": {}}
	current := map[string]garage.BucketKeyPerms{
		"a": {Read: true, Owner: true}, "b": {Write: true}, "denied": {Read: true},
	}
	holdManagedGrantsWhileUnresolved(desired, targets, current, map[string]struct{}{"denied": {}})
	if desired["a"] != (garage.BucketKeyPerms{Read: true, Owner: true}) || desired["b"] != (garage.BucketKeyPerms{Write: true}) {
		t.Fatalf("desired=%+v, want current kept for held targets", desired)
	}
	if _, ok := desired["denied"]; ok {
		t.Fatalf("unauthorized target must still be revoked: %+v", desired)
	}
}

// The GarageBucket direction has the same rule: a missing GarageKey in
// spec.keyPermissions must not block grants to the bucket's other keys.
func TestReconcileKeyPermissions_PendingKeyRefDoesNotBlockOtherGrants(t *testing.T) {
	const (
		bucketID = "bucket-pending-keyref"
		oldKeyID = "GKfromdeletedref"
		newKeyID = "GKready"
	)
	s := runtime.NewScheme()
	_ = garagev1beta1.AddToScheme(s)
	ready := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "ready-key", Namespace: testNamespace},
		Spec:       garagev1beta1.GarageKeySpec{ClusterRef: garagev1beta1.ClusterReference{Name: testClusterName}},
		Status:     garagev1beta1.GarageKeyStatus{AccessKeyID: newKeyID},
	}
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket", Namespace: testNamespace, Generation: 2},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: testClusterName},
			KeyPermissions: []garagev1beta1.KeyPermission{
				{KeyRef: garagev1beta1.KeyRef{Name: "deleted-key"}, Read: true},
				{KeyRef: garagev1beta1.KeyRef{Name: ready.Name}, Write: true},
			},
		},
		Status: garagev1beta1.GarageBucketStatus{BucketID: bucketID, ManagedKeyGrants: []string{oldKeyID}},
	}
	fc := fake.NewClientBuilder().WithScheme(s).WithObjects(ready, bucket).
		WithStatusSubresource(&garagev1beta1.GarageBucket{}).Build()
	r := &GarageBucketReconciler{Client: fc, Scheme: s}
	var allows []garage.AllowBucketKeyRequest
	var denies []garage.DenyBucketKeyRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/v2/AllowBucketKey":
			var body garage.AllowBucketKeyRequest
			_ = json.NewDecoder(req.Body).Decode(&body)
			allows = append(allows, body)
		case "/v2/DenyBucketKey":
			var body garage.DenyBucketKeyRequest
			_ = json.NewDecoder(req.Body).Decode(&body)
			denies = append(denies, body)
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	existing := &garage.Bucket{ID: bucketID, Keys: []garage.BucketKeyInfo{{
		AccessKeyID: oldKeyID, Permissions: garage.BucketKeyPerms{Read: true},
	}}}
	err := r.reconcileKeyPermissions(context.Background(), bucket, garage.NewClient(srv.URL, "tok"), existing)
	if err == nil || !strings.Contains(err.Error(), "deleted-key") {
		t.Fatalf("err=%v, want the pending keyRef reported", err)
	}
	if len(allows) != 1 || allows[0].AccessKeyID != newKeyID || !allows[0].Permissions.Write {
		t.Fatalf("allows=%+v, want Write granted to %s despite the pending ref", allows, newKeyID)
	}
	if len(denies) != 0 {
		t.Fatalf("denies=%+v, want no revocation while a ref is unresolved", denies)
	}
	if !stringSliceContains(bucket.Status.ManagedKeyGrants, oldKeyID) {
		t.Fatalf("managed grants=%v, want %s still reserved", bucket.Status.ManagedKeyGrants, oldKeyID)
	}
}
