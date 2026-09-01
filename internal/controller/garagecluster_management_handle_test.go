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
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

type namespaceRecordingReader struct {
	client.Reader
	rejectClusterWide bool
	rejectNamespaced  bool
	namespaces        []string
}

func (r *namespaceRecordingReader) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	listOptions := &client.ListOptions{}
	for _, option := range options {
		option.ApplyToList(listOptions)
	}
	r.namespaces = append(r.namespaces, listOptions.Namespace)
	if r.rejectClusterWide && listOptions.Namespace == "" {
		return stderrors.New("namespace-scoped APIReader received an unauthorized all-namespace List")
	}
	if r.rejectNamespaced && listOptions.Namespace != "" {
		return stderrors.New("cluster-scoped APIReader unexpectedly received a namespaced List")
	}
	return r.Reader.List(ctx, list, options...)
}

type listRejectingClient struct {
	client.Client
}

func (listRejectingClient) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return stderrors.New("cluster-scoped dependent sweep did not use its authoritative APIReader")
}

func managementHandleScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, appsv1.AddToScheme,
		garagev1beta1.AddToScheme, garagev1beta2.AddToScheme,
	} {
		if err := add(s); err != nil {
			t.Fatalf("AddToScheme: %v", err)
		}
	}
	return s
}

func newHandle(endpoint string) (*garagev1beta2.GarageCluster, *corev1.Secret) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: mhSecret, Namespace: mhNS},
		Data:       map[string][]byte{DefaultAdminTokenKey: []byte("prefix.secret")},
	}
	handle := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:       mhName,
			Namespace:  mhNS,
			Finalizers: []string{garageClusterFinalizer},
		},
		Spec: garagev1beta2.GarageClusterSpec{
			ConnectTo: &garagev1beta2.ConnectToConfig{
				AdminAPIEndpoint:    endpoint,
				AdminTokenSecretRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: mhSecret}, Key: DefaultAdminTokenKey},
			},
		},
	}
	return handle, secret
}

func TestManagementHandleFinalizerDeletesReferencingBucketsAndKeys(t *testing.T) {
	handle, _ := newHandle("http://garage.example:3903")
	matchingKey := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "matching-key", Namespace: mhNS},
		Spec:       garagev1beta1.GarageKeySpec{ClusterRef: garagev1beta1.ClusterReference{Name: mhName}},
	}
	matchingBucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "matching-bucket", Namespace: "tenant"},
		Spec: garagev1beta1.GarageBucketSpec{ClusterRef: garagev1beta1.ClusterReference{
			Name: mhName, Namespace: mhNS,
		}},
	}
	unrelated := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "tenant"},
		Spec:       garagev1beta1.GarageBucketSpec{ClusterRef: garagev1beta1.ClusterReference{Name: "other", Namespace: mhNS}},
	}
	fc := fake.NewClientBuilder().WithScheme(managementHandleScheme(t)).WithObjects(handle, matchingKey, matchingBucket, unrelated).Build()
	reader := &namespaceRecordingReader{Reader: fc, rejectClusterWide: true}
	r := &GarageClusterReconciler{
		Client: listRejectingClient{Client: fc}, APIReader: reader, Scheme: fc.Scheme(), ClusterScoped: false,
		WatchNamespaces: []string{mhNS, "tenant"},
	}

	pending, err := r.deleteGarageResourceDependents(context.Background(), handle)
	if err != nil {
		t.Fatal(err)
	}
	if !pending {
		t.Fatal("dependents were not reported pending before deletion")
	}
	if want := []string{mhNS, "tenant", mhNS, "tenant", mhNS, "tenant"}; !slices.Equal(reader.namespaces, want) {
		t.Fatalf("namespace-scoped APIReader List scopes = %v, want %v", reader.namespaces, want)
	}
	keyRef := types.NamespacedName{Name: matchingKey.Name, Namespace: matchingKey.Namespace}
	bucketRef := types.NamespacedName{Name: matchingBucket.Name, Namespace: matchingBucket.Namespace}
	protectedKey := &garagev1beta1.GarageKey{}
	if err := fc.Get(context.Background(), keyRef, protectedKey); err != nil {
		t.Fatalf("dependent key disappeared before its finalizer was attached: %v", err)
	}
	if len(protectedKey.Finalizers) != 1 || protectedKey.Finalizers[0] != garageKeyFinalizer || !protectedKey.DeletionTimestamp.IsZero() {
		t.Fatalf("first sweep key finalization state = finalizers %v, deletionTimestamp %v", protectedKey.Finalizers, protectedKey.DeletionTimestamp)
	}
	protectedBucket := &garagev1beta1.GarageBucket{}
	if err := fc.Get(context.Background(), bucketRef, protectedBucket); err != nil {
		t.Fatalf("dependent bucket disappeared before its finalizer was attached: %v", err)
	}
	if len(protectedBucket.Finalizers) != 1 || protectedBucket.Finalizers[0] != garageBucketFinalizer || !protectedBucket.DeletionTimestamp.IsZero() {
		t.Fatalf("first sweep bucket finalization state = finalizers %v, deletionTimestamp %v", protectedBucket.Finalizers, protectedBucket.DeletionTimestamp)
	}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: unrelated.Name, Namespace: unrelated.Namespace}, &garagev1beta1.GarageBucket{}); err != nil {
		t.Fatalf("unrelated bucket was deleted: %v", err)
	}

	pending, err = r.deleteGarageResourceDependents(context.Background(), handle)
	if err != nil || !pending {
		t.Fatalf("second dependent sweep pending=%v err=%v, want deletion in progress", pending, err)
	}
	deletingKey := &garagev1beta1.GarageKey{}
	if err := fc.Get(context.Background(), keyRef, deletingKey); err != nil || deletingKey.DeletionTimestamp.IsZero() {
		t.Fatalf("second sweep did not start protected key deletion: timestamp=%v err=%v", deletingKey.DeletionTimestamp, err)
	}
	deletingBucket := &garagev1beta1.GarageBucket{}
	if err := fc.Get(context.Background(), bucketRef, deletingBucket); err != nil || deletingBucket.DeletionTimestamp.IsZero() {
		t.Fatalf("second sweep did not start protected bucket deletion: timestamp=%v err=%v", deletingBucket.DeletionTimestamp, err)
	}

	// Stand in for the child controllers completing their external Garage cleanup.
	deletingKey.Finalizers = nil
	if err := fc.Update(context.Background(), deletingKey); err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("release key finalizer: %v", err)
	}
	deletingBucket.Finalizers = nil
	if err := fc.Update(context.Background(), deletingBucket); err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("release bucket finalizer: %v", err)
	}
	pending, err = r.deleteGarageResourceDependents(context.Background(), handle)
	if err != nil || pending {
		t.Fatalf("terminal dependent sweep pending=%v err=%v, want complete", pending, err)
	}
}

func TestManagementHandleFinalizationConvergesAfterReferenceGrantRevocation(t *testing.T) {
	ctx := t.Context()
	handle, secret := newHandle("http://garage.example:3903")
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cross-key", Namespace: "tenant", Finalizers: []string{garageKeyFinalizer},
		},
		Spec: garagev1beta1.GarageKeySpec{
			Name:       "cross-key",
			ClusterRef: garagev1beta1.ClusterReference{Name: handle.Name, Namespace: handle.Namespace},
			AllBuckets: &garagev1beta1.AllBucketsPermission{Read: true},
		},
	}
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cross-bucket", Namespace: "tenant", Finalizers: []string{garageBucketFinalizer},
		},
		Spec: garagev1beta1.GarageBucketSpec{
			ClusterRef:  garagev1beta1.ClusterReference{Name: handle.Name, Namespace: handle.Namespace},
			GlobalAlias: "cross-bucket",
		},
	}
	grant := &garagev1beta1.GarageReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-dependents", Namespace: handle.Namespace},
		Spec: garagev1beta1.GarageReferenceGrantSpec{
			From: []garagev1beta1.ReferenceGrantFrom{
				{Kind: "GarageKey", Namespace: key.Namespace},
				{Kind: "GarageBucket", Namespace: bucket.Namespace},
			},
			To: []garagev1beta1.ReferenceGrantTo{{Kind: "GarageCluster", Name: handle.Name}},
		},
	}
	scheme := managementHandleScheme(t)
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(handle, secret, key, bucket, grant).Build()
	keyValidator := &garagev1beta1.GarageKeyValidator{Client: base}
	bucketValidator := &garagev1beta1.GarageBucketValidator{Client: base}
	if _, err := keyValidator.ValidateCreate(ctx, key); err != nil {
		t.Fatalf("initial key grant: %v", err)
	}
	if _, err := bucketValidator.ValidateCreate(ctx, bucket); err != nil {
		t.Fatalf("initial bucket grant: %v", err)
	}
	if err := base.Delete(ctx, grant); err != nil {
		t.Fatalf("revoke GarageReferenceGrant: %v", err)
	}

	r := &GarageClusterReconciler{Client: base, APIReader: base, Scheme: scheme, ClusterScoped: true}
	if err := r.finalize(ctx, handle); err == nil || !strings.Contains(err.Error(), "GarageBucket and GarageKey dependents") {
		t.Fatalf("first parent finalization error = %v, want dependent barrier", err)
	}

	deletingKey := &garagev1beta1.GarageKey{}
	if err := base.Get(ctx, client.ObjectKeyFromObject(key), deletingKey); err != nil {
		t.Fatalf("get deleting key: %v", err)
	}
	keyCleanup := deletingKey.DeepCopy()
	keyCleanup.Finalizers = nil
	if _, err := keyValidator.ValidateUpdate(ctx, deletingKey, keyCleanup); err != nil {
		t.Fatalf("revoked grant stranded key finalizer removal: %v", err)
	}
	if err := base.Update(ctx, keyCleanup); err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("release key finalizer: %v", err)
	}

	deletingBucket := &garagev1beta1.GarageBucket{}
	if err := base.Get(ctx, client.ObjectKeyFromObject(bucket), deletingBucket); err != nil {
		t.Fatalf("get deleting bucket: %v", err)
	}
	bucketCleanup := deletingBucket.DeepCopy()
	bucketCleanup.Finalizers = nil
	if _, err := bucketValidator.ValidateUpdate(ctx, deletingBucket, bucketCleanup); err != nil {
		t.Fatalf("revoked grant stranded bucket finalizer removal: %v", err)
	}
	if err := base.Update(ctx, bucketCleanup); err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("release bucket finalizer: %v", err)
	}

	if err := r.finalize(ctx, handle); err != nil {
		t.Fatalf("parent finalization did not converge after grant revocation: %v", err)
	}
}

func TestManagementHandleFinalizerUsesAPIReaderForClusterScopedCrossNamespaceDependents(t *testing.T) {
	handle, _ := newHandle("http://garage.example:3903")
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "cross-namespace", Namespace: "tenant"},
		Spec: garagev1beta1.GarageBucketSpec{ClusterRef: garagev1beta1.ClusterReference{
			Name: handle.Name, Namespace: handle.Namespace,
		}},
	}
	base := fake.NewClientBuilder().WithScheme(managementHandleScheme(t)).WithObjects(handle, bucket).Build()
	reader := &namespaceRecordingReader{Reader: base, rejectNamespaced: true}
	r := &GarageClusterReconciler{
		Client: listRejectingClient{Client: base}, APIReader: reader, Scheme: base.Scheme(), ClusterScoped: true,
	}

	pending, err := r.deleteGarageResourceDependents(t.Context(), handle)
	if err != nil || !pending {
		t.Fatalf("cluster-scoped dependent sweep pending=%v err=%v", pending, err)
	}
	if want := []string{"", "", ""}; !slices.Equal(reader.namespaces, want) {
		t.Fatalf("cluster-scoped APIReader List scopes = %v, want %v", reader.namespaces, want)
	}
	protected := &garagev1beta1.GarageBucket{}
	if err := base.Get(t.Context(), client.ObjectKeyFromObject(bucket), protected); err != nil {
		t.Fatal(err)
	}
	if len(protected.Finalizers) != 1 || protected.Finalizers[0] != garageBucketFinalizer {
		t.Fatalf("cross-namespace dependent finalizers = %v, want %q", protected.Finalizers, garageBucketFinalizer)
	}
}

func TestStorageClusterFinalizerWaitsForCrossNamespaceGarageDependents(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: mhName, Namespace: mhNS, UID: "storage-cluster-uid"},
		Spec: garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{
			Replicas: 1, Metadata: &garagev1beta2.VolumeConfig{}, Data: &garagev1beta2.VolumeConfig{},
		}},
	}
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "cross-namespace", Namespace: "tenant"},
		Spec: garagev1beta1.GarageBucketSpec{ClusterRef: garagev1beta1.ClusterReference{
			Name: cluster.Name, Namespace: cluster.Namespace,
		}},
	}
	base := fake.NewClientBuilder().WithScheme(managementHandleScheme(t)).WithObjects(cluster, bucket).Build()
	r := &GarageClusterReconciler{Client: base, APIReader: base, Scheme: base.Scheme(), ClusterScoped: true}

	err := r.finalize(t.Context(), cluster)
	if err == nil || !strings.Contains(err.Error(), "GarageBucket and GarageKey dependents") {
		t.Fatalf("finalize error = %v, want dependent barrier", err)
	}
	protected := &garagev1beta1.GarageBucket{}
	if err := base.Get(t.Context(), client.ObjectKeyFromObject(bucket), protected); err != nil {
		t.Fatal(err)
	}
	if !controllerutil.ContainsFinalizer(protected, garageBucketFinalizer) {
		t.Fatalf("cross-namespace dependent finalizers = %v", protected.Finalizers)
	}
}

func TestStorageClusterFinalizerFindsDependentsThroughHandleChains(t *testing.T) {
	storage := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "storage", Namespace: mhNS, UID: "storage-uid"},
		Spec: garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{
			Replicas: 1, Metadata: &garagev1beta2.VolumeConfig{}, Data: &garagev1beta2.VolumeConfig{},
		}},
	}
	handle := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "handle", Namespace: mhNS, UID: "handle-uid"},
		Spec: garagev1beta2.GarageClusterSpec{ConnectTo: &garagev1beta2.ConnectToConfig{
			ClusterRef: &garagev1beta2.ClusterReference{Name: storage.Name},
		}},
	}
	leafHandle := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "leaf-handle", Namespace: mhNS, UID: "leaf-handle-uid"},
		Spec: garagev1beta2.GarageClusterSpec{ConnectTo: &garagev1beta2.ConnectToConfig{
			ClusterRef: &garagev1beta2.ClusterReference{Name: handle.Name},
		}},
	}
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "through-two-handles", Namespace: "tenant"},
		Spec: garagev1beta1.GarageKeySpec{ClusterRef: garagev1beta1.ClusterReference{
			Name: leafHandle.Name, Namespace: leafHandle.Namespace,
		}},
	}
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "through-handle", Namespace: "tenant"},
		Spec: garagev1beta1.GarageBucketSpec{ClusterRef: garagev1beta1.ClusterReference{
			Name: handle.Name, Namespace: handle.Namespace,
		}},
	}
	nodeID := strings.Repeat("a", 64)
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "through-handle-node", Namespace: mhNS, Finalizers: []string{garageNodeFinalizer},
		},
		Spec: garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{
			Name: leafHandle.Name,
		}},
		Status: garagev1beta1.GarageNodeStatus{NodeID: nodeID},
	}
	base := fake.NewClientBuilder().WithScheme(managementHandleScheme(t)).WithObjects(
		storage, handle, leafHandle, key, bucket, node,
	).Build()
	r := &GarageClusterReconciler{Client: base, APIReader: base, Scheme: base.Scheme(), ClusterScoped: true}

	pending, err := r.deleteGarageResourceDependents(t.Context(), storage)
	if err != nil || !pending {
		t.Fatalf("transitive dependent sweep pending=%v err=%v", pending, err)
	}
	for _, dependent := range []client.Object{key, bucket} {
		fresh := dependent.DeepCopyObject().(client.Object)
		if err := base.Get(t.Context(), client.ObjectKeyFromObject(dependent), fresh); err != nil {
			t.Fatal(err)
		}
		if len(fresh.GetFinalizers()) != 1 {
			t.Fatalf("dependent %T %s finalizers = %v", dependent, dependent.GetName(), fresh.GetFinalizers())
		}
	}
	for _, survivingHandle := range []*garagev1beta2.GarageCluster{handle, leafHandle} {
		fresh := &garagev1beta2.GarageCluster{}
		if err := base.Get(t.Context(), client.ObjectKeyFromObject(survivingHandle), fresh); err != nil {
			t.Fatalf("handle %s was removed before its dependents finalized: %v", survivingHandle.Name, err)
		}
	}
	nodeIDs, err := r.collectGarageNodeIDs(t.Context(), storage)
	if err != nil || !nodeIDs[nodeID] {
		t.Fatalf("transitive GarageNode inventory IDs=%v err=%v", nodeIDs, err)
	}
	pendingNodes, err := r.deleteReferencingGarageNodes(t.Context(), storage)
	if err != nil || !pendingNodes {
		t.Fatalf("transitive GarageNode deletion pending=%v err=%v", pendingNodes, err)
	}
	deletingNode := &garagev1beta1.GarageNode{}
	if err := base.Get(t.Context(), client.ObjectKeyFromObject(node), deletingNode); err != nil || deletingNode.DeletionTimestamp.IsZero() {
		t.Fatalf("transitive GarageNode was not retained for finalization: timestamp=%v err=%v", deletingNode.DeletionTimestamp, err)
	}
}

func TestDeletingTransitiveGarageNodeAcceptsCanonicalRootDrainHandoff(t *testing.T) {
	now := metav1.Now()
	root := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "storage-root", Namespace: mhNS, UID: "storage-root-uid",
			DeletionTimestamp: &now, Finalizers: []string{garageClusterFinalizer},
		},
		Spec: garagev1beta2.GarageClusterSpec{
			Storage:        &garagev1beta2.StorageSpec{Replicas: 1},
			DeletionPolicy: garagev1beta2.DeletionPolicyDrain,
		},
	}
	handle := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "surviving-handle", Namespace: mhNS, UID: "handle-uid"},
		Spec: garagev1beta2.GarageClusterSpec{
			LayoutPolicy: LayoutPolicyManual,
			ConnectTo:    &garagev1beta2.ConnectToConfig{ClusterRef: &garagev1beta2.ClusterReference{Name: root.Name}},
		},
	}
	nodeID := strings.Repeat("d", 64)
	proof, err := storageDrainRemovalIntent(
		nil, storageDrainActorForCluster(root), []string{nodeID}, []string{nodeID}, time.Now().Add(-time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	completedAt := metav1.Now()
	proof.CompletedAt = &completedAt
	root.Status.StorageDrain = v1beta2StorageDrainStatus(proof)
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "transitive-node", Namespace: mhNS, UID: "transitive-node-uid",
			DeletionTimestamp: &now, Finalizers: []string{garageNodeFinalizer},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: handle.Name},
			External:   &garagev1beta1.ExternalNodeConfig{Address: "garage.example.test"},
		},
		Status: garagev1beta1.GarageNodeStatus{NodeID: nodeID},
	}
	scheme := managementHandleScheme(t)
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(root, handle, node).
		WithStatusSubresource(&garagev1beta1.GarageNode{}, &garagev1beta2.GarageCluster{}).Build()
	r := &GarageNodeReconciler{
		Client: base, APIReader: base, Scheme: scheme, ClusterScoped: true,
		LayoutMutations: NewLayoutMutationCoordinator(),
	}

	result, err := r.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(node)})
	if err != nil || result != (reconcile.Result{}) {
		t.Fatalf("transitive node terminal handoff result=%+v err=%v", result, err)
	}
	if err := base.Get(t.Context(), client.ObjectKeyFromObject(node), &garagev1beta1.GarageNode{}); !apierrors.IsNotFound(err) {
		t.Fatalf("transitive GarageNode remained after canonical root terminal handoff: %v", err)
	}
}

func TestDeletingDependentsFinalizeThroughDeletingRootHandle(t *testing.T) {
	var keyDeletes atomic.Int32
	var bucketDeletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/v2/DeleteKey":
			if req.URL.Query().Get("id") != "GKcleanupthroughroot000001" {
				t.Errorf("DeleteKey id = %q", req.URL.Query().Get("id"))
			}
			keyDeletes.Add(1)
		case "/v2/DeleteBucket":
			if req.URL.Query().Get("id") != "cleanup-bucket-id" {
				t.Errorf("DeleteBucket id = %q", req.URL.Query().Get("id"))
			}
			bucketDeletes.Add(1)
		default:
			t.Errorf("unexpected Garage request path %q", req.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	root, secret := newHandle(server.URL)
	now := metav1.Now()
	root.DeletionTimestamp = &now
	leaf := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "cleanup-leaf", Namespace: root.Namespace},
		Spec: garagev1beta2.GarageClusterSpec{ConnectTo: &garagev1beta2.ConnectToConfig{
			ClusterRef: &garagev1beta2.ClusterReference{Name: root.Name},
		}},
	}
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cleanup-key", Namespace: root.Namespace, DeletionTimestamp: &now,
			Finalizers: []string{garageKeyFinalizer},
		},
		Spec:   garagev1beta1.GarageKeySpec{ClusterRef: garagev1beta1.ClusterReference{Name: leaf.Name}},
		Status: garagev1beta1.GarageKeyStatus{AccessKeyID: "GKcleanupthroughroot000001"},
	}
	bucket := &garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cleanup-bucket", Namespace: root.Namespace, DeletionTimestamp: &now,
			Finalizers: []string{garageBucketFinalizer},
		},
		Spec:   garagev1beta1.GarageBucketSpec{ClusterRef: garagev1beta1.ClusterReference{Name: leaf.Name}},
		Status: garagev1beta1.GarageBucketStatus{BucketID: "cleanup-bucket-id"},
	}
	scheme := managementHandleScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(root, secret, leaf, key, bucket).
		WithStatusSubresource(&garagev1beta1.GarageKey{}, &garagev1beta1.GarageBucket{}).Build()

	keyReconciler := &GarageKeyReconciler{Client: kubeClient, Scheme: scheme}
	if result, err := keyReconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(key)}); err != nil || result != (reconcile.Result{}) {
		t.Fatalf("deleting key Reconcile result=%+v err=%v", result, err)
	}
	bucketReconciler := &GarageBucketReconciler{Client: kubeClient, Scheme: scheme}
	if result, err := bucketReconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(bucket)}); err != nil || result != (reconcile.Result{}) {
		t.Fatalf("deleting bucket Reconcile result=%+v err=%v", result, err)
	}
	if keyDeletes.Load() != 1 || bucketDeletes.Load() != 1 {
		t.Fatalf("Garage cleanup calls: keys=%d buckets=%d, want one each", keyDeletes.Load(), bucketDeletes.Load())
	}
	if err := kubeClient.Get(t.Context(), client.ObjectKeyFromObject(key), &garagev1beta1.GarageKey{}); !apierrors.IsNotFound(err) {
		t.Fatalf("key remains after finalizer release: %v", err)
	}
	if err := kubeClient.Get(t.Context(), client.ObjectKeyFromObject(bucket), &garagev1beta1.GarageBucket{}); !apierrors.IsNotFound(err) {
		t.Fatalf("bucket remains after finalizer release: %v", err)
	}
}

func TestNewGarageKeyCannotMutateDeletingManagementHandle(t *testing.T) {
	var adminCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		adminCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	handle, secret := newHandle(server.URL)
	now := metav1.Now()
	handle.DeletionTimestamp = &now
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "late-key", Namespace: handle.Namespace},
		Spec:       garagev1beta1.GarageKeySpec{ClusterRef: garagev1beta1.ClusterReference{Name: handle.Name}},
	}
	scheme := managementHandleScheme(t)
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(handle, secret, key).
		WithStatusSubresource(&garagev1beta1.GarageKey{}).Build()
	reconciler := &GarageKeyReconciler{Client: base, Scheme: scheme}

	result, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(key)})
	if err != nil || result.RequeueAfter != RequeueAfterUnhealthy {
		t.Fatalf("late dependent Reconcile result=%+v err=%v", result, err)
	}
	fresh := &garagev1beta1.GarageKey{}
	if err := base.Get(t.Context(), client.ObjectKeyFromObject(key), fresh); err != nil {
		t.Fatal(err)
	}
	if len(fresh.Finalizers) != 0 {
		t.Fatalf("late dependent acquired finalizer before deleting-cluster guard: %v", fresh.Finalizers)
	}
	condition := meta.FindStatusCondition(fresh.Status.Conditions, PhaseReady)
	if fresh.Status.Phase != PhasePending || condition == nil || condition.Reason != garagev1beta1.ReasonClusterNotReady {
		t.Fatalf("late dependent status=%+v ready=%+v", fresh.Status, condition)
	}
	if adminCalls.Load() != 0 {
		t.Fatalf("deleting management handle received %d Admin API calls from late dependent", adminCalls.Load())
	}
}

// Reachable external Admin API → Phase Running, ManagementHandleReady True, and
// no managed workload created (no STS, ConfigMap, or Service).
func TestReconcileManagementHandle_ReachableSetsRunning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"layoutVersion":1,"nodes":[]}`))
	}))
	defer srv.Close()

	handle, secret := newHandle(srv.URL)
	s := managementHandleScheme(t)
	fc := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(handle, secret).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		Build()
	r := &GarageClusterReconciler{Client: fc, Scheme: s, ClusterDomain: testClusterDomain}

	if _, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: mhName, Namespace: mhNS},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := &garagev1beta2.GarageCluster{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: mhName, Namespace: mhNS}, got); err != nil {
		t.Fatalf("get cluster: %v", err)
	}
	if got.Status.Phase != PhaseRunning {
		t.Errorf("Phase = %q, want %q", got.Status.Phase, PhaseRunning)
	}
	if c := meta.FindStatusCondition(got.Status.Conditions, garagev1beta1.ConditionManagementHandleReady); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("ManagementHandleReady condition = %+v, want True", c)
	}

	// No managed workload should exist for a handle.
	sts := &appsv1.StatefulSet{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: mhName, Namespace: mhNS}, sts); err == nil {
		t.Error("a StatefulSet was created for a management handle, want none")
	}
	cm := &corev1.ConfigMap{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: mhName, Namespace: mhNS}, cm); err == nil {
		t.Error("a ConfigMap was created for a management handle, want none")
	}
	svc := &corev1.Service{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: mhName, Namespace: mhNS}, svc); err == nil {
		t.Error("a Service was created for a management handle, want none")
	}
	generatedRPC := &corev1.Secret{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: defaultRPCSecretName(handle), Namespace: mhNS}, generatedRPC); !apierrors.IsNotFound(err) {
		t.Errorf("generated RPC Secret lookup error = %v, want NotFound for an Admin-only handle", err)
	}
}

// Explicit RPC identity sources on a management handle are copied into the
// same immutable local snapshot contract used by managed workloads. This lets
// GarageKey derive deterministic credentials without following a mutable
// external Secret or provisioning any Garage workload for the handle.
func TestReconcileManagementHandle_PinsExplicitRPCIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"layoutVersion":1,"nodes":[]}`))
	}))
	defer srv.Close()

	for _, tc := range []struct {
		name      string
		configure func(*garagev1beta2.GarageCluster, *corev1.SecretKeySelector)
	}{
		{
			name: "network rpcSecretRef",
			configure: func(handle *garagev1beta2.GarageCluster, ref *corev1.SecretKeySelector) {
				handle.Spec.Network.RPCSecretRef = ref
			},
		},
		{
			name: "connectTo rpcSecretRef",
			configure: func(handle *garagev1beta2.GarageCluster, ref *corev1.SecretKeySelector) {
				handle.Spec.ConnectTo.RPCSecretRef = ref
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handle, adminSecret := newHandle(srv.URL)
			handle.UID = types.UID("management-handle-uid")
			rpcSource := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "external-rpc", Namespace: mhNS},
				Data:       map[string][]byte{RPCSecretKey: []byte(strings.Repeat("a", 64))},
			}
			ref := &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: rpcSource.Name},
				Key:                  RPCSecretKey,
			}
			tc.configure(handle, ref)

			s := managementHandleScheme(t)
			fc := fake.NewClientBuilder().
				WithScheme(s).
				WithObjects(handle, adminSecret, rpcSource).
				WithStatusSubresource(&garagev1beta2.GarageCluster{}).
				Build()
			r := &GarageClusterReconciler{Client: fc, Scheme: s, ClusterDomain: testClusterDomain}

			if _, err := r.Reconcile(context.Background(), reconcile.Request{
				NamespacedName: types.NamespacedName{Name: mhName, Namespace: mhNS},
			}); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}

			gotHandle := &garagev1beta2.GarageCluster{}
			if err := fc.Get(context.Background(), types.NamespacedName{Name: mhName, Namespace: mhNS}, gotHandle); err != nil {
				t.Fatalf("get handle: %v", err)
			}
			if gotHandle.Status.Phase != PhaseRunning {
				t.Fatalf("Phase = %q, want %q", gotHandle.Status.Phase, PhaseRunning)
			}
			if gotHandle.Annotations[annotationRPCIdentitySHA256] == "" {
				t.Fatal("handle did not persist the pinned RPC identity fingerprint")
			}

			snapshot := &corev1.Secret{}
			if err := fc.Get(context.Background(), types.NamespacedName{Name: mhName + "-rpc-secret-snapshot", Namespace: mhNS}, snapshot); err != nil {
				t.Fatalf("get RPC identity snapshot: %v", err)
			}
			if snapshot.Immutable == nil || !*snapshot.Immutable {
				t.Fatal("RPC identity snapshot is not immutable")
			}
			if got, want := string(snapshot.Data[RPCSecretKey]), strings.Repeat("a", 64); got != want {
				t.Errorf("snapshot RPC identity = %q, want %q", got, want)
			}
			if !metav1.IsControlledBy(snapshot, gotHandle) {
				t.Errorf("snapshot ownerReferences = %+v, want handle controller owner", snapshot.OwnerReferences)
			}
		})
	}
}

// Unreachable external Admin API → Phase Pending, condition False.
func TestReconcileManagementHandle_UnreachableSetsPending(t *testing.T) {
	// Point at a closed server so the dial fails fast.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}))
	url := srv.URL
	srv.Close()

	handle, secret := newHandle(url)
	s := managementHandleScheme(t)
	fc := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(handle, secret).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}).
		Build()
	r := &GarageClusterReconciler{Client: fc, Scheme: s, ClusterDomain: testClusterDomain}

	if _, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: mhName, Namespace: mhNS},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := &garagev1beta2.GarageCluster{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: mhName, Namespace: mhNS}, got); err != nil {
		t.Fatalf("get cluster: %v", err)
	}
	if got.Status.Phase != PhasePending {
		t.Errorf("Phase = %q, want %q", got.Status.Phase, PhasePending)
	}
	if c := meta.FindStatusCondition(got.Status.Conditions, garagev1beta1.ConditionManagementHandleReady); c == nil || c.Status != metav1.ConditionFalse {
		t.Errorf("ManagementHandleReady condition = %+v, want False", c)
	}
}

// A management handle that never published an observed S3 endpoint leaves
// nothing to infer — its Service does not exist — so endpoint-bearing generated
// Secrets must fail closed with actionable guidance.
func TestReconcileSecret_ManagementHandleRequiresExplicitEndpoint(t *testing.T) {
	handle := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: mhName, Namespace: mhNS},
		Spec: garagev1beta2.GarageClusterSpec{
			ConnectTo: &garagev1beta2.ConnectToConfig{AdminAPIEndpoint: mhEndpoint},
		},
	}
	key := &garagev1beta1.GarageKey{ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: mhNS}}
	key.Status.AccessKeyID = "GKtest"

	s := managementHandleScheme(t)
	fc := fake.NewClientBuilder().WithScheme(s).Build()
	r := &GarageKeyReconciler{Client: fc, Scheme: s, ClusterDomain: testClusterDomain}

	err := r.reconcileSecret(context.Background(), key, handle, "sk")
	if err == nil || !strings.Contains(err.Error(), "secretTemplate.includeEndpoint=false") {
		t.Fatalf("reconcileSecret error = %v, want actionable endpoint configuration failure", err)
	}
}

// A handle's Secret must use the endpoint the cluster controller derived onto
// status, not fail closed.
func TestReconcileSecret_ManagementHandleUsesObservedS3Endpoint(t *testing.T) {
	handle := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: mhName, Namespace: mhNS},
		Spec: garagev1beta2.GarageClusterSpec{
			ConnectTo: &garagev1beta2.ConnectToConfig{AdminAPIEndpoint: mhEndpoint},
		},
	}
	handle.Status.Endpoints = &garagev1beta2.ClusterEndpoints{S3: "http://garage.garage.svc:3900"}
	key := &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: mhNS, UID: types.UID("key-uid")},
	}
	key.Status.AccessKeyID = "GKtest"

	s := managementHandleScheme(t)
	fc := fake.NewClientBuilder().WithScheme(s).
		WithObjects(key).WithStatusSubresource(&garagev1beta1.GarageKey{}).Build()
	r := &GarageKeyReconciler{Client: fc, Scheme: s, ClusterDomain: testClusterDomain}

	if err := r.reconcileSecret(context.Background(), key, handle, "sk"); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}

	secret := &corev1.Secret{}
	if err := fc.Get(context.Background(), types.NamespacedName{Name: "k", Namespace: mhNS}, secret); err != nil {
		t.Fatalf("get generated secret: %v", err)
	}
	for k, want := range map[string]string{
		defaultEndpointKey: "http://garage.garage.svc:3900",
		defaultHostKey:     "garage.garage.svc:3900",
		defaultSchemeKey:   "http",
	} {
		if got := string(secret.Data[k]); got != want {
			t.Errorf("secret[%q] = %q, want %q", k, got, want)
		}
	}
}

// status.endpoints.s3 is written in two formats (managed: "host:port", handle:
// a full URL); both must resolve, and a handle has no Service to fall back to.
func TestResolveS3Endpoint(t *testing.T) {
	cluster := func(spec garagev1beta2.GarageClusterSpec, s3 string) *garagev1beta2.GarageCluster {
		c := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: mhName, Namespace: mhNS}, Spec: spec,
		}
		if s3 != "" {
			c.Status.Endpoints = &garagev1beta2.ClusterEndpoints{S3: s3}
		}
		return c
	}
	handle := garagev1beta2.GarageClusterSpec{
		ConnectTo: &garagev1beta2.ConnectToConfig{AdminAPIEndpoint: mhEndpoint},
	}
	managed := garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{Replicas: 3}}
	fqdn := svcFQDN(mhName, mhNS, DefaultS3Port, testClusterDomain)

	tests := []struct {
		name            string
		cluster         *garagev1beta2.GarageCluster
		wantURL, wantIn string
	}{
		{"handle URL", cluster(handle, "http://backup.garage.svc:3900"), "http://backup.garage.svc:3900", ""},
		{"handle https", cluster(handle, "https://s3.example.com:3900"), "https://s3.example.com:3900", ""},
		{"managed host:port", cluster(managed, fqdn), "http://" + fqdn, ""},
		{"managed falls back to its Service", cluster(managed, ""), "http://" + fqdn, ""},
		{"handle has no fallback", cluster(handle, ""), "", "no observed S3 endpoint"},
		{"unusable value", cluster(handle, "ftp://backup.garage.svc:3900"), "", "invalid Garage S3 endpoint"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveS3Endpoint(tt.cluster, testClusterDomain)
			if tt.wantIn != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantIn) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantIn)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveS3Endpoint: %v", err)
			}
			if got.String() != tt.wantURL {
				t.Errorf("endpoint = %q, want %q", got, tt.wantURL)
			}
		})
	}
}
