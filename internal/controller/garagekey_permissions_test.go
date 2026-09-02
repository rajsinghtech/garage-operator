package controller

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

type failGarageKeySecretDeleteOnceClient struct {
	client.Client
	name   string
	failed bool
}

func (c *failGarageKeySecretDeleteOnceClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if !c.failed && obj.GetName() == c.name {
		c.failed = true
		return stderrors.New("injected crash-window delete failure")
	}
	return c.Client.Delete(ctx, obj, opts...)
}

func TestUpdateKeyIfNeeded_DowngradesCreateBucket(t *testing.T) {
	var body garage.UpdateKeyRequestBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v2/UpdateKey" || req.URL.Query().Get("id") != "GKkey" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewDecoder(req.Body).Decode(&body)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	key := &garagev1beta1.GarageKey{Spec: garagev1beta1.GarageKeySpec{Permissions: &garagev1beta1.KeyPermissions{CreateBucket: false}}}
	existing := &garage.Key{AccessKeyID: "GKkey", Permissions: garage.KeyPermissions{CreateBucket: true}}
	r := &GarageKeyReconciler{}
	if err := r.updateKeyIfNeeded(context.Background(), key, garage.NewClient(srv.URL, "tok"), existing); err != nil {
		t.Fatal(err)
	}
	if body.Allow != nil || body.Deny == nil || !body.Deny.CreateBucket {
		t.Fatalf("update body=%+v, want deny.createBucket=true and no allow", body)
	}
}

func TestGetOrCreateKey_ImportDoesNotAdoptUnrelatedSameNameKey(t *testing.T) {
	const (
		requestedKeyID     = "GKrequested"
		requestedKeySecret = "requested-secret"
	)
	var listCalls int
	var imported garage.ImportKeyRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/v2/ListKeys":
			listCalls++
			_, _ = w.Write([]byte(`[{"id":"GKunrelated","name":"shared-name"}]`))
		case "/v2/ImportKey":
			if err := json.NewDecoder(req.Body).Decode(&imported); err != nil {
				t.Errorf("decode import: %v", err)
			}
			_, _ = w.Write([]byte(`{"accessKeyId":"` + requestedKeyID + `","secretAccessKey":"` + requestedKeySecret + `","name":"shared-name","permissions":{},"buckets":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-name", Namespace: testNamespace, UID: "shared-name-uid"},
		Spec: garagev1beta1.GarageKeySpec{ImportKey: &garagev1beta1.ImportKeyConfig{
			AccessKeyID: requestedKeyID, SecretAccessKey: requestedKeySecret,
		}},
	}
	scheme := runtime.NewScheme()
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	r := &GarageKeyReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(key).Build(), Scheme: scheme}
	got, secret, err := r.getOrCreateKey(context.Background(), key, &garagev1beta2.GarageCluster{}, garage.NewClient(srv.URL, "tok"), key.Name)
	if err != nil {
		t.Fatal(err)
	}
	if listCalls != 0 {
		t.Fatalf("ListKeys calls = %d, want 0; key names are not ownership", listCalls)
	}
	if imported.AccessKeyID != requestedKeyID || imported.SecretAccessKey != requestedKeySecret {
		t.Fatalf("import request = %+v", imported)
	}
	if got.AccessKeyID != requestedKeyID || secret != requestedKeySecret {
		t.Fatalf("result = %+v secret=%q, want explicitly imported key", got, secret)
	}
}

func TestReconcileSecret_RefusesForeignExistingSecret(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = garagev1beta1.AddToScheme(scheme)
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: testNamespace, UID: types.UID("key-uid")},
		Status:     garagev1beta1.GarageKeyStatus{AccessKeyID: "GKowned"},
	}
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
		Data:       map[string][]byte{"keep": []byte("foreign")},
	}
	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(key, foreign).Build()
	r := &GarageKeyReconciler{Client: fc, Scheme: scheme, ClusterDomain: "cluster.local"}
	err := r.reconcileSecret(context.Background(), key, &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: defaultAppName, Namespace: testNamespace},
	}, "new-secret")
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("err=%v, want foreign Secret ownership failure", err)
	}
	got := &corev1.Secret{}
	if getErr := fc.Get(context.Background(), types.NamespacedName{Name: key.Name, Namespace: key.Namespace}, got); getErr != nil {
		t.Fatal(getErr)
	}
	if string(got.Data["keep"]) != "foreign" || len(got.Data) != 1 {
		t.Fatalf("foreign Secret was mutated: %#v", got.Data)
	}
}

func TestReconcileSecret_RetryCleansOldSecretAfterPersistedHandoff(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = garagev1beta1.AddToScheme(scheme)
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: testNamespace, UID: types.UID("key-uid")},
		Spec: garagev1beta1.GarageKeySpec{
			SecretTemplate: &garagev1beta1.SecretTemplate{Name: "new-key"},
		},
		Status: garagev1beta1.GarageKeyStatus{
			AccessKeyID: "GKowned",
			SecretRef:   &corev1.SecretReference{Name: "old-key", Namespace: testNamespace},
		},
	}
	old := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "old-key", Namespace: testNamespace}}
	if err := controllerutil.SetControllerReference(key, old, scheme); err != nil {
		t.Fatal(err)
	}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(key, old).
		WithStatusSubresource(&garagev1beta1.GarageKey{}).Build()
	fault := &failGarageKeySecretDeleteOnceClient{Client: base, name: old.Name}
	r := &GarageKeyReconciler{Client: fault, Scheme: scheme, ClusterDomain: "cluster.local"}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: defaultAppName, Namespace: testNamespace}}

	err := r.reconcileSecret(t.Context(), key, cluster, "secret")
	if err == nil || !strings.Contains(err.Error(), "injected crash-window") {
		t.Fatalf("first reconcile error = %v, want injected post-status delete failure", err)
	}
	fresh := &garagev1beta1.GarageKey{}
	if err := base.Get(t.Context(), client.ObjectKeyFromObject(key), fresh); err != nil {
		t.Fatal(err)
	}
	if fresh.Status.SecretRef == nil || fresh.Status.SecretRef.Name != "new-key" {
		t.Fatalf("secretRef = %+v, want persisted new-key before delete", fresh.Status.SecretRef)
	}
	if err := base.Get(t.Context(), types.NamespacedName{Name: old.Name, Namespace: old.Namespace}, &corev1.Secret{}); err != nil {
		t.Fatalf("old Secret missing before retry: %v", err)
	}

	if err := r.reconcileSecret(t.Context(), fresh, cluster, "secret"); err != nil {
		t.Fatalf("retry reconcileSecret: %v", err)
	}
	if err := base.Get(t.Context(), types.NamespacedName{Name: old.Name, Namespace: old.Namespace}, &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Fatalf("old Secret still exists after retry, get error = %v", err)
	}
}

func TestReconcileSecret_RotationUpdatesCredentialsFile(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = garagev1beta1.AddToScheme(scheme)
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: testNamespace, UID: types.UID("key-uid")},
		Spec: garagev1beta1.GarageKeySpec{SecretTemplate: &garagev1beta1.SecretTemplate{
			IncludeEndpoint:        boolPtr(false),
			IncludeRegion:          boolPtr(false),
			IncludeCredentialsFile: boolPtr(true),
		}},
		Status: garagev1beta1.GarageKeyStatus{
			AccessKeyID: "GKrotated",
			SecretRef:   &corev1.SecretReference{Name: "key", Namespace: testNamespace},
		},
	}
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
		Data: map[string][]byte{
			defaultAccessKeyIDKey:     []byte("GKrotated"),
			defaultSecretAccessKeyKey: []byte("old-secret"),
			defaultCredentialsFileKey: []byte("[default]\naws_access_key_id=GKrotated\naws_secret_access_key=old-secret\n"),
		},
	}
	if err := controllerutil.SetControllerReference(key, existing, scheme); err != nil {
		t.Fatal(err)
	}
	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(key, existing).Build()
	r := &GarageKeyReconciler{Client: fc, Scheme: scheme, ClusterDomain: "cluster.local"}

	if err := r.reconcileSecret(t.Context(), key, &garagev1beta2.GarageCluster{}, "new-secret"); err != nil {
		t.Fatal(err)
	}
	got := &corev1.Secret{}
	if err := fc.Get(t.Context(), client.ObjectKeyFromObject(existing), got); err != nil {
		t.Fatal(err)
	}
	if value := string(got.Data[defaultSecretAccessKeyKey]); value != "new-secret" {
		t.Fatalf("secret access key = %q, want new-secret", value)
	}
	wantFile := "[default]\naws_access_key_id=GKrotated\naws_secret_access_key=new-secret\n"
	if value := string(got.Data[defaultCredentialsFileKey]); value != wantFile {
		t.Fatalf("credentials file = %q, want %q", value, wantFile)
	}
}

func TestCOSIManagedShadowCleansOnlyGeneratedCredentialSecret(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = garagev1beta1.AddToScheme(scheme)
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cosi-shadow", Namespace: testNamespace, UID: types.UID("cosi-shadow-uid"),
			Labels: map[string]string{garagev1beta1.LabelCOSIManaged: annotationTrue},
			Annotations: map[string]string{
				garagev1beta1.AnnotationCOSIReservationOwner: "ba-access-uid",
			},
		},
		Status: garagev1beta1.GarageKeyStatus{
			AccessKeyID: "GKcosishadow",
			SecretRef:   &corev1.SecretReference{Name: "renamed-generated", Namespace: testNamespace},
		},
	}
	generated := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "renamed-generated", Namespace: testNamespace,
	}}
	if err := controllerutil.SetControllerReference(key, generated, scheme); err != nil {
		t.Fatal(err)
	}
	crashWindow := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: key.Name, Namespace: testNamespace,
	}}
	if err := controllerutil.SetControllerReference(key, crashWindow, scheme); err != nil {
		t.Fatal(err)
	}
	reservation := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "cosi-key-reservation", Namespace: testNamespace,
		Labels: map[string]string{garagev1beta1.LabelCOSIManaged: annotationTrue},
	}}
	tenantCredential := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "claim-credentials", Namespace: "tenant",
		Labels: map[string]string{garagev1beta1.LabelCOSIManaged: annotationTrue},
	}}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		key, generated, crashWindow, reservation, tenantCredential,
	).Build()
	reconciler := &GarageKeyReconciler{Client: base, Scheme: scheme}

	if err := reconciler.cleanupCOSIManagedShadowCredentials(t.Context(), key); err != nil {
		t.Fatalf("cleanup COSI shadow credentials: %v", err)
	}
	if key.Status.SecretRef != nil {
		t.Fatalf("secretRef = %+v, want cleared", key.Status.SecretRef)
	}
	for _, removed := range []*corev1.Secret{generated, crashWindow} {
		if err := base.Get(t.Context(), client.ObjectKeyFromObject(removed), &corev1.Secret{}); !apierrors.IsNotFound(err) {
			t.Fatalf("generated shadow Secret %s still exists: %v", removed.Name, err)
		}
	}
	for _, kept := range []*corev1.Secret{reservation, tenantCredential} {
		if err := base.Get(t.Context(), client.ObjectKeyFromObject(kept), &corev1.Secret{}); err != nil {
			t.Fatalf("unrelated COSI Secret %s/%s was removed: %v", kept.Namespace, kept.Name, err)
		}
	}
}

func TestReconcileManagedBucketPermissions_ExactUnionDowngrade(t *testing.T) {
	const (
		bucketID = "bucket-key-union"
		keyID    = "GKkeyunion"
	)
	s := runtime.NewScheme()
	_ = garagev1beta1.AddToScheme(s)
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: testNamespace},
		Spec: garagev1beta1.GarageKeySpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: testClusterName},
			BucketPermissions: []garagev1beta1.BucketPermission{{
				BucketID: bucketID, Read: true,
			}},
		},
		Status: garagev1beta1.GarageKeyStatus{AccessKeyID: keyID},
	}
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket", Namespace: testNamespace},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: testClusterName},
			BucketID:   bucketID,
			KeyPermissions: []garagev1beta1.KeyPermission{{
				KeyRef: garagev1beta1.KeyRef{Name: key.Name}, Write: true,
			}},
		},
		Status: garagev1beta1.GarageBucketStatus{ManagedKeyGrants: []string{keyID}},
	}
	fc := fake.NewClientBuilder().WithScheme(s).WithObjects(key, bucket).
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
		ID: bucketID, Permissions: garage.BucketKeyPerms{Read: true, Write: true, Owner: true},
	}}}
	if err := r.reconcileManagedBucketPermissions(context.Background(), key, garage.NewClient(srv.URL, "tok"), existing); err != nil {
		t.Fatal(err)
	}
	if len(allows) != 0 {
		t.Fatalf("unexpected allows: %+v", allows)
	}
	if len(denies) != 1 || denies[0].Permissions != (garage.BucketKeyPerms{Owner: true}) {
		t.Fatalf("denies=%+v, want only Owner downgrade", denies)
	}
}

func TestReconcileManagedBucketPermissions_RemovesPriorAllBucketsWithExplicitGrant(t *testing.T) {
	const (
		explicitBucketID = "bucket-explicit"
		staleBucketID    = "bucket-stale-cluster-wide"
		keyID            = "GKclusterwide"
	)
	s := runtime.NewScheme()
	_ = garagev1beta1.AddToScheme(s)
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: testNamespace},
		Spec: garagev1beta1.GarageKeySpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: testClusterName},
			BucketPermissions: []garagev1beta1.BucketPermission{{
				BucketID: explicitBucketID, Read: true,
			}},
		},
		Status: garagev1beta1.GarageKeyStatus{
			AccessKeyID: keyID, ClusterWide: true, ManagedBucketGrants: []string{explicitBucketID},
		},
	}
	fc := fake.NewClientBuilder().WithScheme(s).WithObjects(key).
		WithStatusSubresource(&garagev1beta1.GarageKey{}).Build()
	r := &GarageKeyReconciler{Client: fc, Scheme: s}
	var denies []garage.DenyBucketKeyRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != testDenyBucketKeyPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body garage.DenyBucketKeyRequest
		_ = json.NewDecoder(req.Body).Decode(&body)
		denies = append(denies, body)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	existing := &garage.Key{AccessKeyID: keyID, Buckets: []garage.KeyBucket{
		{ID: explicitBucketID, Permissions: garage.BucketKeyPerms{Read: true}},
		{ID: staleBucketID, Permissions: garage.BucketKeyPerms{Write: true}},
	}}
	if err := r.reconcileManagedBucketPermissions(context.Background(), key, garage.NewClient(srv.URL, "tok"), existing); err != nil {
		t.Fatal(err)
	}
	if len(denies) != 1 || denies[0].BucketID != staleBucketID || !denies[0].Permissions.Write {
		t.Fatalf("denies=%+v, want stale cluster-wide Write revoked", denies)
	}
	if len(key.Status.ManagedBucketGrants) != 1 || key.Status.ManagedBucketGrants[0] != explicitBucketID {
		t.Fatalf("managed grants=%v, want only explicit bucket ID", key.Status.ManagedBucketGrants)
	}
}

func TestReconcileManagedBucketPermissions_AllBucketsDefaultedEmptyPreservesScopedGrant(t *testing.T) {
	const (
		explicitBucketID = "bucket-explicit-migration"
		staleBucketID    = "bucket-stale-migration"
		keyID            = "GKmigration"
	)
	s := runtime.NewScheme()
	if err := garagev1beta1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: testNamespace},
		Spec: garagev1beta1.GarageKeySpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: testClusterName},
			AllBuckets: &garagev1beta1.AllBucketsPermission{Read: true, Write: true},
		},
		Status: garagev1beta1.GarageKeyStatus{AccessKeyID: keyID},
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(key).
		WithStatusSubresource(&garagev1beta1.GarageKey{}).Build()
	var allows []garage.AllowBucketKeyRequest
	var denies []garage.DenyBucketKeyRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/ListBuckets":
			_, _ = w.Write([]byte(`[{"id":"bucket-explicit-migration"},{"id":"bucket-stale-migration"}]`))
			return
		case testAllowBucketKeyPath:
			var body garage.AllowBucketKeyRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode allow request: %v", err)
			}
			allows = append(allows, body)
		case testDenyBucketKeyPath:
			var body garage.DenyBucketKeyRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode deny request: %v", err)
			}
			denies = append(denies, body)
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	r := &GarageKeyReconciler{Client: c, Scheme: s}
	garageClient := garage.NewClient(server.URL, "token")
	remote := &garage.Key{AccessKeyID: keyID}

	// Establish the remote state from the original allBuckets declaration.
	if err := r.reconcileManagedBucketPermissions(t.Context(), key, garageClient, remote); err != nil {
		t.Fatalf("initial allBuckets reconcile: %v", err)
	}
	if len(allows) != 2 {
		t.Fatalf("initial allow requests = %d, want one per bucket", len(allows))
	}

	// Model the server-side-apply result: the omitted field can remain as an
	// all-false object after nested CRD defaults are applied.
	migrated := &garagev1beta1.GarageKey{}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(key), migrated); err != nil {
		t.Fatal(err)
	}
	migrated.Spec.AllBuckets = &garagev1beta1.AllBucketsPermission{}
	migrated.Spec.BucketPermissions = []garagev1beta1.BucketPermission{{
		BucketID: explicitBucketID,
		Read:     true,
	}}
	if err := c.Update(t.Context(), migrated); err != nil {
		t.Fatal(err)
	}

	allows = nil
	denies = nil
	remote.Buckets = []garage.KeyBucket{
		{ID: explicitBucketID, Permissions: garage.BucketKeyPerms{Read: true, Write: true}},
		{ID: staleBucketID, Permissions: garage.BucketKeyPerms{Read: true, Write: true}},
	}
	if err := r.reconcileManagedBucketPermissions(t.Context(), migrated, garageClient, remote); err != nil {
		t.Fatalf("scoped migration reconcile: %v", err)
	}
	if len(allows) != 0 {
		t.Fatalf("migration unexpectedly allowed permissions: %+v", allows)
	}
	gotDenies := make(map[string]garage.BucketKeyPerms, len(denies))
	for _, deny := range denies {
		gotDenies[deny.BucketID] = deny.Permissions
	}
	wantDenies := map[string]garage.BucketKeyPerms{
		explicitBucketID: {Write: true},
		staleBucketID:    {Read: true, Write: true},
	}
	if len(gotDenies) != len(wantDenies) {
		t.Fatalf("deny requests = %+v, want %+v", gotDenies, wantDenies)
	}
	for bucketID, want := range wantDenies {
		if gotDenies[bucketID] != want {
			t.Fatalf("deny for %s = %+v, want %+v", bucketID, gotDenies[bucketID], want)
		}
	}
	if !migrated.Status.ClusterWide {
		t.Fatal("cluster-wide ownership was released before the defaulted allBuckets cleanup completed")
	}
	if len(migrated.Status.ManagedBucketGrants) != 1 || migrated.Status.ManagedBucketGrants[0] != explicitBucketID {
		t.Fatalf("managed grants = %v, want [%s]", migrated.Status.ManagedBucketGrants, explicitBucketID)
	}
}

func TestGetOrCreateKey_COSIAnnotationPinsExactID(t *testing.T) {
	const cosiID = "GKcosiexact"
	for _, tc := range []struct {
		name   string
		status int
	}{
		{name: "adopts exact annotated key", status: http.StatusOK},
		{name: "fails closed instead of name-adopting", status: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests = append(requests, req.URL.Path+"?"+req.URL.RawQuery)
				if req.URL.Query().Get("id") != cosiID {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.WriteHeader(tc.status)
				if tc.status == http.StatusOK {
					_, _ = w.Write([]byte(`{"accessKeyId":"GKcosiexact","name":"same-name","permissions":{"createBucket":false},"buckets":[]}`))
				}
			}))
			defer srv.Close()
			key := &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{garagev1beta1.AnnotationCOSIAccountID: cosiID}},
				Spec:       garagev1beta1.GarageKeySpec{Name: "same-name"},
				Status:     garagev1beta1.GarageKeyStatus{AccessKeyID: cosiID},
			}
			r := &GarageKeyReconciler{}
			got, _, err := r.getOrCreateKey(context.Background(), key, &garagev1beta2.GarageCluster{}, garage.NewClient(srv.URL, "tok"), "same-name")
			if tc.status == http.StatusNotFound {
				if err == nil {
					t.Fatal("missing annotated key unexpectedly fell back to name adoption")
				}
			} else if err != nil || got.AccessKeyID != cosiID {
				t.Fatalf("got=%+v err=%v", got, err)
			}
			if len(requests) != 1 || reqPathHasListKeys(requests[0]) {
				t.Fatalf("requests=%v, want one exact-ID lookup and no ListKeys/name adoption", requests)
			}
		})
	}
}

func reqPathHasListKeys(path string) bool {
	return path == "/v2/ListKeys" || path == "/v2/ListKeys?"
}
