package controller

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

type stalePVCNotFoundClient struct{ client.Client }

func (c *stalePVCNotFoundClient) Get(
	ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption,
) error {
	if _, isPVC := object.(*corev1.PersistentVolumeClaim); isPVC {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "persistentvolumeclaims"}, key.Name)
	}
	return c.Client.Get(ctx, key, object, options...)
}

func managedPVCTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, appsv1.AddToScheme,
		garagev1beta1.AddToScheme, garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}

func TestRetainedAutoModePVCHandoffAuthorizesStorageAndGatewayExactUIDs(t *testing.T) {
	for _, tier := range []string{tierStorage, tierGateway} {
		t.Run(tier, func(t *testing.T) {
			controller := true
			cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
				Name: "store", Namespace: "default", UID: "cluster-uid",
			}}
			nonce, hash, err := newManagedNodePVCNonce()
			if err != nil {
				t.Fatal(err)
			}
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "store-" + tier + "-1", Namespace: "default", UID: "new-node-uid",
					Labels: map[string]string{
						labelAutoNodeSlot: "store-" + tier + "-1", labelAppManagedBy: managedByOperatorValue,
						labelTier: tier,
					},
					Annotations: map[string]string{autoModePVCHandoffNonceAnnotation: nonce},
					OwnerReferences: []metav1.OwnerReference{{
						UID: cluster.UID, Controller: &controller,
					}},
				},
				Spec: garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}},
			}
			pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
				Name: "metadata-" + node.Name + "-0", Namespace: node.Namespace, UID: "pvc-uid",
				Annotations: map[string]string{managedPVCNodeUIDAnnotation: "old-node-uid"},
			}}
			cluster.Status.AutoModePVCHandoffs = []garagev1beta2.AutoModePVCHandoffStatus{{
				SlotName: node.Labels[labelAutoNodeSlot], PVCName: pvc.Name, PVCUID: string(pvc.UID),
				PreviousGarageNodeUID: "old-node-uid", ReplacementReservationHash: hash,
				ReplacementGarageNodeUID: string(node.UID),
			}}

			if handoff, err := retainedAutoModePVCHandoff(cluster, node, pvc); err != nil || handoff == nil {
				t.Fatalf("exact %s handoff was not authorized: handoff=%#v err=%v", tier, handoff, err)
			}
			forged := node.DeepCopy()
			forged.UID = "forged-node-uid"
			if _, err := retainedAutoModePVCHandoff(cluster, forged, pvc); err == nil {
				t.Fatalf("%s handoff authorized the wrong GarageNode UID", tier)
			}
		})
	}
}

func TestIssue349LostAutoModeStorageDeletionHandsOffRetainedPVC(t *testing.T) {
	ctx := context.Background()
	scheme := managedPVCTestScheme(t)
	controller := true
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "store", Namespace: "default", UID: "cluster-uid"},
		Spec: garagev1beta2.GarageClusterSpec{
			LayoutPolicy: LayoutPolicyAuto,
			Storage: &garagev1beta2.StorageSpec{
				Replicas: 1,
				Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
				Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
			},
		},
	}
	oldNode := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "store-storage-0", Namespace: "default", UID: "old-node-uid",
			Labels: map[string]string{
				labelCluster:      cluster.Name,
				labelTier:         tierStorage,
				labelAppManagedBy: managedByOperatorValue,
				labelAutoNodeSlot: "store-storage-0",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: garagev1beta2.GroupVersion.String(),
				Kind:       kindGarageCluster,
				Name:       cluster.Name,
				UID:        cluster.UID,
				Controller: &controller,
			}},
		},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
			Capacity:   ptrQuantity(resource.MustParse("10Gi")),
		},
		Status: garagev1beta1.GarageNodeStatus{
			NodeID: "old-garage-node-id",
			ManagedPVCs: []garagev1beta1.ManagedNodePVCStatus{{
				Name: "metadata-store-storage-0-0", UID: "metadata-pvc-uid",
			}},
		},
	}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: "metadata-store-storage-0-0", Namespace: "default", UID: "metadata-pvc-uid",
		Annotations: map[string]string{managedPVCNodeUIDAnnotation: string(oldNode.UID)},
	}}
	fc := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta1.GarageNode{}, &garagev1beta2.GarageCluster{}).
		WithObjects(cluster, oldNode, claim).Build()

	nodeReconciler := &GarageNodeReconciler{Client: fc, APIReader: fc, Scheme: scheme}
	if err := nodeReconciler.prepareAutoModePVCHandoffBeforeFinalization(ctx, oldNode, cluster); err != nil {
		t.Fatalf("lost-source finalization did not preserve the retained PVC handoff: %v", err)
	}
	freshCluster := &garagev1beta2.GarageCluster{}
	if err := fc.Get(ctx, client.ObjectKeyFromObject(cluster), freshCluster); err != nil {
		t.Fatal(err)
	}
	wantHandoff := garagev1beta2.AutoModePVCHandoffStatus{
		SlotName:              "store-storage-0",
		PVCName:               claim.Name,
		PVCUID:                string(claim.UID),
		PreviousGarageNodeUID: string(oldNode.UID),
	}
	if len(freshCluster.Status.AutoModePVCHandoffs) != 1 || freshCluster.Status.AutoModePVCHandoffs[0] != wantHandoff {
		t.Fatalf("unexpected lost-source PVC handoff: got %#v, want %#v", freshCluster.Status.AutoModePVCHandoffs, []garagev1beta2.AutoModePVCHandoffStatus{wantHandoff})
	}

	// The finalizer has now released the old GarageNode. The Auto parent can
	// recreate the same slot, but only after reserving and binding the exact
	// retained claim incarnation recorded above.
	if err := fc.Delete(ctx, oldNode); err != nil {
		t.Fatalf("deleting the finalized old GarageNode: %v", err)
	}
	clusterReconciler := &GarageClusterReconciler{Client: fc, APIReader: fc, Scheme: scheme}
	desired, err := clusterReconciler.buildAutoModeStorageNode(cluster, 0, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	desired.UID = "replacement-node-uid"
	hasHandoff, err := clusterReconciler.reserveAutoModeReplacement(ctx, freshCluster, desired)
	if err != nil {
		t.Fatalf("reserving the retained PVC for the replacement slot: %v", err)
	}
	if !hasHandoff {
		t.Fatal("replacement slot did not see the finalization handoff")
	}
	if err := fc.Create(ctx, desired); err != nil {
		t.Fatalf("creating replacement GarageNode: %v", err)
	}
	if err := clusterReconciler.bindAutoModeReplacement(ctx, freshCluster, desired, desired.Name); err != nil {
		t.Fatalf("binding replacement GarageNode: %v", err)
	}

	if err := nodeReconciler.ensureManagedNodePVCProvenance(ctx, claim, desired, freshCluster); err != nil {
		t.Fatalf("accepting the exact retained PVC on the replacement GarageNode: %v", err)
	}
	persistedClaim := &corev1.PersistentVolumeClaim{}
	if err := fc.Get(ctx, client.ObjectKeyFromObject(claim), persistedClaim); err != nil {
		t.Fatal(err)
	}
	if got := persistedClaim.Annotations[managedPVCNodeUIDAnnotation]; got != string(desired.UID) {
		t.Fatalf("retained PVC was not transferred to replacement GarageNode UID: got %q, want %q", got, desired.UID)
	}
	if !controllerutil.ContainsFinalizer(persistedClaim, managedPVCFinalizer) {
		t.Fatal("replacement claim did not receive its exact-identity barrier")
	}
	persistedNode := &garagev1beta1.GarageNode{}
	if err := fc.Get(ctx, client.ObjectKeyFromObject(desired), persistedNode); err != nil {
		t.Fatal(err)
	}
	wantPVCRecord := garagev1beta1.ManagedNodePVCStatus{Name: claim.Name, UID: claim.UID}
	if len(persistedNode.Status.ManagedPVCs) != 1 || persistedNode.Status.ManagedPVCs[0] != wantPVCRecord {
		t.Fatalf("replacement GarageNode did not record the exact PVC UID: got %#v, want %#v", persistedNode.Status.ManagedPVCs, []garagev1beta1.ManagedNodePVCStatus{wantPVCRecord})
	}

	changed, err := clusterReconciler.reconcileCurrentAutoModePVCHandoffs(ctx, freshCluster, persistedNode, desired.Name)
	if err != nil {
		t.Fatalf("consuming the retained PVC handoff: %v", err)
	}
	if !changed || len(freshCluster.Status.AutoModePVCHandoffs) != 0 {
		t.Fatalf("retained PVC handoff was not cleared after exact replacement consumption: changed=%v status=%#v", changed, freshCluster.Status.AutoModePVCHandoffs)
	}
}

func TestManagedPVCReservationRecoversAfterCreateStatusCrash(t *testing.T) {
	ctx := context.Background()
	nonce, hash, err := newManagedNodePVCNonce()
	if err != nil {
		t.Fatal(err)
	}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "node", Namespace: "default", UID: "node-uid"},
		Status: garagev1beta1.GarageNodeStatus{ManagedPVCs: []garagev1beta1.ManagedNodePVCStatus{{
			Name: "metadata-node-0", PendingReservationHash: hash,
		}}},
	}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: "metadata-node-0", Namespace: "default", UID: "claim-uid",
		Annotations: map[string]string{
			managedPVCNodeUIDAnnotation: string(node.UID),
			managedPVCNonceAnnotation:   nonce,
		},
	}}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "default"}}
	fc := fake.NewClientBuilder().WithScheme(managedPVCTestScheme(t)).
		WithStatusSubresource(&garagev1beta1.GarageNode{}).
		WithObjects(node, claim).Build()
	r := &GarageNodeReconciler{Client: fc}

	templates := []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "metadata"}}}
	if err := r.validateConventionNamedNodePVCs(ctx, node, cluster, templates); err != nil {
		t.Fatalf("recover pending reservation: %v", err)
	}
	if len(node.Status.ManagedPVCs) != 1 || node.Status.ManagedPVCs[0].UID != claim.UID ||
		node.Status.ManagedPVCs[0].PendingReservationHash != "" {
		t.Fatalf("pending reservation was not bound to exact UID: %#v", node.Status.ManagedPVCs)
	}
}

func TestManagedPVCReservationRequiresAdmissionProtection(t *testing.T) {
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "node", Namespace: "default", UID: "node-uid"},
	}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "default"}}
	base := fake.NewClientBuilder().WithScheme(managedPVCTestScheme(t)).WithObjects(node).Build()
	r := &GarageNodeReconciler{Client: base, ManagedPVCAdmissionDisabled: true}
	templates := []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "metadata"}}}

	if err := r.validateConventionNamedNodePVCs(t.Context(), node, cluster, templates); err == nil {
		t.Fatal("managed PVC reservation was accepted without its admission protection")
	}
	claim := &corev1.PersistentVolumeClaim{}
	if err := base.Get(t.Context(), types.NamespacedName{Name: "metadata-node-0", Namespace: "default"}, claim); !apierrors.IsNotFound(err) {
		t.Fatalf("unprotected managed PVC was created: %v", err)
	}
}

func TestStorageRolloutPVCProtectionRequiresAdmission(t *testing.T) {
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: "metadata-node-0", Namespace: "default", UID: "claim-uid",
	}}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
		Name: "cluster", Namespace: "default", UID: "cluster-uid",
	}}
	record := nodeLocalPoolRolloutRecord{
		GarageNodeName: "node",
		PersistentVolumeClaims: []garagev1beta2.StorageRolloutPersistentVolumeClaimStatus{{
			Name: claim.Name, UID: string(claim.UID),
		}},
	}
	base := fake.NewClientBuilder().WithScheme(managedPVCTestScheme(t)).WithObjects(claim).Build()
	r := &GarageClusterReconciler{Client: base, APIReader: base, ManagedPVCAdmissionDisabled: true}

	if err := r.protectStorageRolloutPersistentVolumeClaims(t.Context(), cluster, record); err == nil {
		t.Fatal("storage rollout PVC protection was accepted without its admission boundary")
	}
	persisted := &corev1.PersistentVolumeClaim{}
	if err := base.Get(t.Context(), client.ObjectKeyFromObject(claim), persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted.Finalizers) != 0 {
		t.Fatalf("unprotected storage rollout mutated PVC finalizers: %v", persisted.Finalizers)
	}
}

func TestManagedPVCReservationRejectsWrongNonce(t *testing.T) {
	ctx := context.Background()
	_, hash, err := newManagedNodePVCNonce()
	if err != nil {
		t.Fatal(err)
	}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "node", Namespace: "default", UID: "node-uid"},
		Status: garagev1beta1.GarageNodeStatus{ManagedPVCs: []garagev1beta1.ManagedNodePVCStatus{{
			Name: "metadata-node-0", PendingReservationHash: hash,
		}}},
	}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: "metadata-node-0", Namespace: "default", UID: "claim-uid",
		Annotations: map[string]string{
			managedPVCNodeUIDAnnotation: string(node.UID),
			managedPVCNonceAnnotation:   "attacker-selected-nonce",
		},
	}}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "default"}}
	fc := fake.NewClientBuilder().WithScheme(managedPVCTestScheme(t)).
		WithStatusSubresource(&garagev1beta1.GarageNode{}).
		WithObjects(node, claim).Build()
	r := &GarageNodeReconciler{Client: fc}

	templates := []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "metadata"}}}
	if err := r.validateConventionNamedNodePVCs(ctx, node, cluster, templates); err == nil {
		t.Fatal("wrong reservation nonce was accepted")
	}
}

func TestManagedPVCReservationUsesAuthoritativeReaderAfterStaleNotFound(t *testing.T) {
	ctx := context.Background()
	nonce, hash, err := newManagedNodePVCNonce()
	if err != nil {
		t.Fatal(err)
	}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "node", Namespace: "default", UID: "node-uid"},
		Status: garagev1beta1.GarageNodeStatus{ManagedPVCs: []garagev1beta1.ManagedNodePVCStatus{{
			Name: "metadata-node-0", PendingReservationHash: hash,
		}}},
	}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: "metadata-node-0", Namespace: "default", UID: "claim-uid",
		Annotations: map[string]string{
			managedPVCNodeUIDAnnotation: string(node.UID), managedPVCNonceAnnotation: nonce,
		},
	}}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "default"}}
	base := fake.NewClientBuilder().WithScheme(managedPVCTestScheme(t)).
		WithStatusSubresource(&garagev1beta1.GarageNode{}).
		WithObjects(node, claim).Build()
	r := &GarageNodeReconciler{Client: &stalePVCNotFoundClient{Client: base}, APIReader: base}

	templates := []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "metadata"}}}
	if err := r.validateConventionNamedNodePVCs(ctx, node, cluster, templates); err != nil {
		t.Fatalf("authoritative PVC read did not recover existing commitment: %v", err)
	}
	if node.Status.ManagedPVCs[0].UID != claim.UID || node.Status.ManagedPVCs[0].PendingReservationHash != "" {
		t.Fatalf("existing pending commitment was rotated instead of bound: %#v", node.Status.ManagedPVCs)
	}
}

func TestManagedPVCReservationRejectsAuthoritativeReplacementDespiteCachedIdentity(t *testing.T) {
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "node", Namespace: "default", UID: "node-uid"},
		Status: garagev1beta1.GarageNodeStatus{ManagedPVCs: []garagev1beta1.ManagedNodePVCStatus{{
			Name: "metadata-node-0", UID: "recorded-uid",
		}}},
	}
	cachedClaim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: "metadata-node-0", Namespace: "default", UID: "recorded-uid",
	}}
	replacement := cachedClaim.DeepCopy()
	replacement.UID = "replacement-uid"
	scheme := managedPVCTestScheme(t)
	cached := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cachedClaim).Build()
	authoritative := fake.NewClientBuilder().WithScheme(scheme).WithObjects(replacement).Build()
	r := &GarageNodeReconciler{Client: cached, APIReader: authoritative}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "default"}}
	templates := []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "metadata"}}}
	if err := r.validateConventionNamedNodePVCs(t.Context(), node, cluster, templates); err == nil {
		t.Fatal("authoritative same-name PVC replacement was accepted from stale cached identity")
	}
}

func TestManagedPVCReplacementBarrierPreventsCheckUseRecreation(t *testing.T) {
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "node", Namespace: "default", UID: "node-uid"},
		Status: garagev1beta1.GarageNodeStatus{ManagedPVCs: []garagev1beta1.ManagedNodePVCStatus{{
			Name: "metadata-node-0", UID: "claim-uid",
		}}},
	}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: "metadata-node-0", Namespace: "default", UID: "claim-uid",
	}}
	base := fake.NewClientBuilder().WithScheme(managedPVCTestScheme(t)).WithObjects(claim).Build()
	r := &GarageNodeReconciler{Client: base, APIReader: base}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "default"}}
	templates := []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "metadata"}}}
	if err := r.validateConventionNamedNodePVCs(t.Context(), node, cluster, templates); err != nil {
		t.Fatal(err)
	}
	persisted := &corev1.PersistentVolumeClaim{}
	if err := base.Get(t.Context(), client.ObjectKeyFromObject(claim), persisted); err != nil {
		t.Fatal(err)
	}
	if !controllerutil.ContainsFinalizer(persisted, managedPVCFinalizer) {
		t.Fatal("unadopted exact PVC lacks its replacement barrier")
	}
	if err := base.Delete(t.Context(), persisted); err != nil {
		t.Fatal(err)
	}
	terminating := &corev1.PersistentVolumeClaim{}
	if err := base.Get(t.Context(), client.ObjectKeyFromObject(claim), terminating); err != nil {
		t.Fatalf("barrier did not retain terminating exact claim: %v", err)
	}
	if terminating.DeletionTimestamp.IsZero() {
		t.Fatal("delete did not mark barrier-protected claim terminating")
	}
	replacement := claim.DeepCopy()
	replacement.ResourceVersion = ""
	replacement.UID = "replacement-uid"
	if err := base.Create(t.Context(), replacement); !apierrors.IsAlreadyExists(err) {
		t.Fatalf("same-name replacement raced provenance check: %v", err)
	}
}

func TestManagedPVCReplacementBarrierReleasesAfterExactStatefulSetControl(t *testing.T) {
	scheme := managedPVCTestScheme(t)
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "node", Namespace: "default", UID: "node-uid"},
		Status: garagev1beta1.GarageNodeStatus{ManagedPVCs: []garagev1beta1.ManagedNodePVCStatus{{
			Name: "metadata-node-0", UID: "claim-uid",
		}}},
	}
	statefulSet := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
		Name: node.Name, Namespace: node.Namespace, UID: "statefulset-uid",
	}}
	if err := controllerutil.SetControllerReference(node, statefulSet, scheme); err != nil {
		t.Fatal(err)
	}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: "metadata-node-0", Namespace: "default", UID: "claim-uid", Finalizers: []string{managedPVCFinalizer},
	}}
	if err := controllerutil.SetControllerReference(statefulSet, claim, scheme); err != nil {
		t.Fatal(err)
	}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(statefulSet, claim).Build()
	r := &GarageNodeReconciler{Client: base, APIReader: base}
	cluster := &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "default"}}
	templates := []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "metadata"}}}
	if err := r.validateConventionNamedNodePVCs(t.Context(), node, cluster, templates); err != nil {
		t.Fatal(err)
	}
	persisted := &corev1.PersistentVolumeClaim{}
	if err := base.Get(t.Context(), client.ObjectKeyFromObject(claim), persisted); err != nil {
		t.Fatal(err)
	}
	if controllerutil.ContainsFinalizer(persisted, managedPVCFinalizer) {
		t.Fatal("replacement barrier remained after exact StatefulSet control was authoritative")
	}
}

func TestCleanupOwnerlessManagedNodePVCsHonorsIdentityAndPolicy(t *testing.T) {
	tests := []struct {
		name       string
		policy     string
		recorded   types.UID
		live       types.UID
		wantDelete bool
	}{
		{name: "delete exact ownerless reservation", policy: pvcRetentionDelete, recorded: "claim-uid", live: "claim-uid", wantDelete: true},
		{name: "retain exact ownerless reservation", policy: "Retain", recorded: "claim-uid", live: "claim-uid", wantDelete: false},
		{name: "preserve same-name replacement", policy: pvcRetentionDelete, recorded: "old-claim-uid", live: "replacement-uid", wantDelete: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: "node", Namespace: "default", UID: "node-uid"},
				Status: garagev1beta1.GarageNodeStatus{ManagedPVCs: []garagev1beta1.ManagedNodePVCStatus{{
					Name: "metadata-node-0", UID: tt.recorded,
				}}},
			}
			claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
				Name: "metadata-node-0", Namespace: "default", UID: tt.live, Finalizers: []string{managedPVCFinalizer},
			}}
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "default"},
				Spec: garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{
					PVCRetentionPolicy: &garagev1beta2.PVCRetentionPolicy{WhenDeleted: tt.policy},
				}},
			}
			fc := fake.NewClientBuilder().WithScheme(managedPVCTestScheme(t)).WithObjects(claim).Build()
			r := &GarageNodeReconciler{Client: fc}
			if err := r.cleanupOwnerlessManagedNodePVCs(ctx, node, cluster); err != nil {
				t.Fatal(err)
			}
			got := &corev1.PersistentVolumeClaim{}
			err := fc.Get(ctx, client.ObjectKeyFromObject(claim), got)
			if tt.wantDelete && !apierrors.IsNotFound(err) {
				t.Fatalf("exact ownerless claim was not deleted: %v", err)
			}
			if !tt.wantDelete && err != nil {
				t.Fatalf("claim should have been preserved: %v", err)
			}
			if !tt.wantDelete && tt.live == tt.recorded && controllerutil.ContainsFinalizer(got, managedPVCFinalizer) {
				t.Fatal("Retain preserved the exact claim with a stale controller replacement barrier")
			}
		})
	}
}

func TestCleanupOwnerlessManagedNodePVCsDeletesAuthenticatedPendingClaim(t *testing.T) {
	ctx := context.Background()
	nonce, hash, err := newManagedNodePVCNonce()
	if err != nil {
		t.Fatal(err)
	}
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "node", Namespace: "default", UID: "node-uid"},
		Status: garagev1beta1.GarageNodeStatus{ManagedPVCs: []garagev1beta1.ManagedNodePVCStatus{{
			Name: "metadata-node-0", PendingReservationHash: hash,
		}}},
	}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: "metadata-node-0", Namespace: "default", UID: "claim-uid",
		Annotations: map[string]string{
			managedPVCNodeUIDAnnotation: string(node.UID), managedPVCNonceAnnotation: nonce,
		},
	}}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "default"},
		Spec: garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{
			PVCRetentionPolicy: &garagev1beta2.PVCRetentionPolicy{WhenDeleted: pvcRetentionDelete},
		}},
	}
	fc := fake.NewClientBuilder().WithScheme(managedPVCTestScheme(t)).WithObjects(claim).Build()
	r := &GarageNodeReconciler{Client: fc}
	if err := r.cleanupOwnerlessManagedNodePVCs(ctx, node, cluster); err != nil {
		t.Fatal(err)
	}
	if err := fc.Get(ctx, client.ObjectKeyFromObject(claim), &corev1.PersistentVolumeClaim{}); !apierrors.IsNotFound(err) {
		t.Fatalf("authenticated pending claim was not deleted: %v", err)
	}
}

func TestCleanupOwnerlessManagedNodePVCsUsesAuthoritativeReader(t *testing.T) {
	node := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "node", Namespace: "default", UID: "node-uid"},
		Status: garagev1beta1.GarageNodeStatus{ManagedPVCs: []garagev1beta1.ManagedNodePVCStatus{{
			Name: "metadata-node-0", UID: "claim-uid",
		}}},
	}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
		Name: "metadata-node-0", Namespace: "default", UID: "claim-uid",
	}}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "default"},
		Spec: garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{
			PVCRetentionPolicy: &garagev1beta2.PVCRetentionPolicy{WhenDeleted: pvcRetentionDelete},
		}},
	}
	base := fake.NewClientBuilder().WithScheme(managedPVCTestScheme(t)).WithObjects(claim).Build()
	r := &GarageNodeReconciler{Client: &stalePVCNotFoundClient{Client: base}, APIReader: base}
	if err := r.cleanupOwnerlessManagedNodePVCs(t.Context(), node, cluster); err != nil {
		t.Fatal(err)
	}
	if err := base.Get(t.Context(), client.ObjectKeyFromObject(claim), &corev1.PersistentVolumeClaim{}); !apierrors.IsNotFound(err) {
		t.Fatalf("authoritatively present ownerless claim was leaked: %v", err)
	}
}
