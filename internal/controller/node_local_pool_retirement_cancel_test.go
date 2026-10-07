package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// reselectedRetirementFixture reproduces #470: the Kubernetes Node is selected
// by the pool again, its HostPath claim is persisted as retiring, no GarageNode
// exists for the pair, and its exact Garage role is still committed in a
// settled layout (members == replication factor, so it can never drain).
type reselectedRetirementFixture struct {
	cluster   *garagev1beta2.GarageCluster
	pool      *garagev1beta2.NodeLocalPoolSpec
	node      *corev1.Node
	daemonSet *appsv1.DaemonSet
	layout    *garage.ClusterLayout
	history   *garage.LayoutHistoryResponse
	claimKey  string
	recovery  string
	label     string
}

func newReselectedRetirementFixture(t *testing.T, name string) *reselectedRetirementFixture {
	t.Helper()
	cluster := nodeLocalPoolActivationTestCluster(name, "a")
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	claim, err := newNodeLocalPoolHostPathClaim(cluster, pool, testTerminalNodeID)
	if err != nil {
		t.Fatal(err)
	}
	claim.Retiring = true
	claimValue, err := encodeNodeLocalPoolHostPathClaim(claim)
	if err != nil {
		t.Fatal(err)
	}
	f := &reselectedRetirementFixture{
		cluster:  cluster,
		pool:     pool,
		claimKey: nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name),
		recovery: nodeLocalPoolRecoveryNodeIDAnnotation(cluster, pool.Name),
		label:    nodeLocalPoolActivationLabel(cluster, pool.Name),
	}
	f.node = &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name:   testKubernetesWorkerA,
		UID:    types.UID(name + "-node-uid"),
		Labels: map[string]string{testStorageOwnerLabelKey: "a"},
		Annotations: map[string]string{
			f.claimKey: claimValue,
			f.recovery: testTerminalNodeID,
		},
	}}
	f.daemonSet = &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Name: storageDaemonSetName(cluster, pool.Name), Namespace: cluster.Namespace,
		UID:    types.UID(name + "-daemonset-uid"),
		Labels: map[string]string{labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: pool.Name},
		Annotations: map[string]string{
			annotationNodeLocalPoolActivationValue: nodeLocalPoolActivationLabelValue,
		},
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
			cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster),
		)},
	}}
	capacity := uint64(100 << 30)
	f.layout = &garage.ClusterLayout{Version: 7, Roles: []garage.LayoutNodeRole{
		{ID: testTerminalNodeID, Zone: testZone, Capacity: &capacity},
	}}
	f.history = &garage.LayoutHistoryResponse{
		CurrentVersion: 7,
		Versions:       []garage.LayoutVersion{{Version: 7, Status: garage.LayoutVersionStatusCurrent}},
	}
	return f
}

func (f *reselectedRetirementFixture) reconciler(c client.Client, scheme *runtime.Scheme) *GarageClusterReconciler {
	r := &GarageClusterReconciler{
		Client: c, APIReader: c, Scheme: scheme, ClusterScoped: true,
		LayoutMutations:            NewLayoutMutationCoordinator(),
		NodeLocalPoolPrerequisites: supportedNodeLocalPoolPrerequisites(),
	}
	r.nodeLocalPoolLayoutGetter = func(context.Context, *garagev1beta2.GarageCluster) (*garage.ClusterLayout, error) {
		return f.layout, nil
	}
	r.layoutHistoryGetter = func(context.Context, *garagev1beta2.GarageCluster) (*garage.LayoutHistoryResponse, error) {
		return f.history, nil
	}
	return r
}

func (f *reselectedRetirementFixture) transition(r *GarageClusterReconciler) *nodeLocalPoolLifecycleTransition {
	return &nodeLocalPoolLifecycleTransition{
		reconciler:   r,
		ctx:          context.Background(),
		cluster:      f.cluster,
		configHashes: map[string]string{f.pool.Name: "config-hash"},
	}
}

func (f *reselectedRetirementFixture) freshClaim(t *testing.T, c client.Client) (*nodeLocalPoolHostPathClaim, *corev1.Node) {
	t.Helper()
	fresh := &corev1.Node{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(f.node), fresh); err != nil {
		t.Fatal(err)
	}
	claim, err := decodeNodeLocalPoolHostPathClaim(fresh.Annotations[f.claimKey])
	if err != nil {
		t.Fatal(err)
	}
	return claim, fresh
}

// TestReselectedRetiringNodeWithCommittedRoleRejoins is the #470 regression:
// on main the persisted retirement excludes the reselected Node forever and
// activation refuses the retiring claim.
func TestReselectedRetiringNodeWithCommittedRoleRejoins(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newReselectedRetirementFixture(t, "retiring-rejoin")
	scheme := deletionTestScheme(t)
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(f.cluster, f.node, f.daemonSet).Build()
	r := f.reconciler(kubeClient, scheme)
	transition := f.transition(r)

	result := transition.preflight()
	if result.Err != nil || result.Stop {
		t.Fatalf("preflight() = %+v, want continue", result)
	}
	key := nodeLocalPoolKey(f.pool.Name, f.node.Name)
	if transition.persistedRetirements[key] {
		t.Fatal("reselected Node with a committed role stayed in the persisted retirement set")
	}
	desired := transition.states[f.pool.Name].desiredNodes[f.node.Name]
	if desired == nil {
		t.Fatal("reselected Node was not projected back into desired membership")
	}
	claim, fresh := f.freshClaim(t, kubeClient)
	if claim.Retiring || canonicalGarageNodeID(claim.GarageNodeID) != testTerminalNodeID ||
		fresh.Annotations[f.recovery] != testTerminalNodeID {
		t.Fatalf("cancellation lost the retained identity: claim=%+v annotations=%v", claim, fresh.Annotations)
	}
	if _, active := fresh.Labels[f.label]; active {
		t.Fatal("cancellation must not activate the Node itself; activation runs through the ordinary recovery path")
	}

	// The ordinary recovery activation now accepts the same identity.
	if err := r.ensureNodeLocalPoolActivation(
		ctx, f.cluster, f.pool, desired, f.label, nodeLocalPoolActivationLabelValue,
		f.recovery, testTerminalNodeID,
	); err != nil {
		t.Fatalf("recovery activation after cancellation: %v", err)
	}
	_, fresh = f.freshClaim(t, kubeClient)
	if fresh.Labels[f.label] != nodeLocalPoolActivationLabelValue {
		t.Fatalf("reselected Node was not re-enrolled: labels=%v", fresh.Labels)
	}

	// A second preflight is a fixed point: no further Node writes.
	before := fresh.ResourceVersion
	if result := f.transition(r).preflight(); result.Err != nil || result.Stop {
		t.Fatalf("second preflight() = %+v", result)
	}
	_, fresh = f.freshClaim(t, kubeClient)
	if fresh.ResourceVersion != before {
		t.Fatal("converged cancellation rewrote the Kubernetes Node")
	}
}

func TestReselectedRetiringNodeKeepsRetirementWhenCancellationIsUnsafe(t *testing.T) {
	t.Parallel()
	otherID := strings.Repeat("b", 64)
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, f *reselectedRetirementFixture, r *GarageClusterReconciler) []client.Object
	}{
		{
			name: "GarageNode still exists for the pair",
			mutate: func(t *testing.T, f *reselectedRetirementFixture, _ *GarageClusterReconciler) []client.Object {
				return []client.Object{&garagev1beta1.GarageNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "garage-a-worker-a", Namespace: f.cluster.Namespace,
						Labels: map[string]string{
							labelCluster: f.cluster.Name, labelTier: tierStorage,
							labelAppManagedBy: managedByOperatorValue, labelNodeLocalPool: f.pool.Name,
						},
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
							f.cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster),
						)},
					},
					Spec: garagev1beta1.GarageNodeSpec{
						ClusterRef:         garagev1beta1.ClusterReference{Name: f.cluster.Name},
						Backing:            garagev1beta1.NodeBackingNodeLocalPool,
						NodeLocalPoolName:  f.pool.Name,
						KubernetesNodeName: f.node.Name,
					},
				}}
			},
		},
		{
			name: "role already absent from the committed layout",
			mutate: func(_ *testing.T, f *reselectedRetirementFixture, _ *GarageClusterReconciler) []client.Object {
				f.layout.Roles = nil
				return nil
			},
		},
		{
			name: "role is a gateway role",
			mutate: func(_ *testing.T, f *reselectedRetirementFixture, _ *GarageClusterReconciler) []client.Object {
				f.layout.Roles[0].Capacity = nil
				return nil
			},
		},
		{
			name: "layout has staged role changes",
			mutate: func(_ *testing.T, f *reselectedRetirementFixture, _ *GarageClusterReconciler) []client.Object {
				f.layout.StagedRoleChanges = []garage.NodeRoleChange{{ID: testTerminalNodeID, Remove: true}}
				return nil
			},
		},
		{
			name: "layout history is still draining",
			mutate: func(_ *testing.T, f *reselectedRetirementFixture, _ *GarageClusterReconciler) []client.Object {
				f.history.Versions = append(f.history.Versions,
					garage.LayoutVersion{Version: 6, Status: garage.LayoutVersionStatusDraining})
				return nil
			},
		},
		{
			name: "layout and history versions differ",
			mutate: func(_ *testing.T, f *reselectedRetirementFixture, _ *GarageClusterReconciler) []client.Object {
				f.history.CurrentVersion = 8
				return nil
			},
		},
		{
			name: "membership staging bridge is in flight",
			mutate: func(_ *testing.T, f *reselectedRetirementFixture, _ *GarageClusterReconciler) []client.Object {
				f.daemonSet.Annotations[annotationNodeLocalPoolMembershipStaging] = "staged-target"
				return nil
			},
		},
		{
			name: "claim and recovery pin disagree",
			mutate: func(_ *testing.T, f *reselectedRetirementFixture, _ *GarageClusterReconciler) []client.Object {
				f.node.Annotations[f.recovery] = otherID
				return nil
			},
		},
		{
			name: "claim carries no identity",
			mutate: func(t *testing.T, f *reselectedRetirementFixture, _ *GarageClusterReconciler) []client.Object {
				claim, err := newNodeLocalPoolHostPathClaim(f.cluster, f.pool, "")
				if err != nil {
					t.Fatal(err)
				}
				claim.Retiring = true
				value, err := encodeNodeLocalPoolHostPathClaim(claim)
				if err != nil {
					t.Fatal(err)
				}
				f.node.Annotations[f.claimKey] = value
				delete(f.node.Annotations, f.recovery)
				return nil
			},
		},
		{
			name: "another layout writer holds the mutex",
			mutate: func(t *testing.T, f *reselectedRetirementFixture, r *GarageClusterReconciler) []client.Object {
				release, err := acquireLayoutMutationUnconditionally(r.LayoutMutations, layoutOwnerKey(f.cluster))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(release)
				return nil
			},
		},
		{
			name: "cluster storage drain is active",
			mutate: func(_ *testing.T, f *reselectedRetirementFixture, _ *GarageClusterReconciler) []client.Object {
				f.cluster.Annotations = map[string]string{garagev1beta1.AnnotationDrain: annotationTrue}
				return nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newReselectedRetirementFixture(t, "retiring-keep-"+fmt.Sprint(len(test.name)))
			scheme := deletionTestScheme(t)
			// The reconciler is built before the client so mutex holders can
			// share its coordinator; the client is attached below.
			r := f.reconciler(nil, scheme)
			extra := test.mutate(t, f, r)
			objects := append([]client.Object{f.cluster, f.node, f.daemonSet}, extra...)
			kubeClient := fake.NewClientBuilder().WithScheme(scheme).
				WithStatusSubresource(&garagev1beta2.GarageCluster{}).
				WithObjects(objects...).Build()
			r.Client, r.APIReader = kubeClient, kubeClient
			originalClaim := f.node.Annotations[f.claimKey]

			_ = f.transition(r).preflight()

			_, fresh := f.freshClaim(t, kubeClient)
			if fresh.Annotations[f.claimKey] != originalClaim {
				t.Fatalf("unsafe cancellation rewrote the retiring claim: %s", fresh.Annotations[f.claimKey])
			}
			if _, active := fresh.Labels[f.label]; active {
				t.Fatal("unsafe cancellation activated the Node")
			}
		})
	}
}

func TestReselectedRetirementCancelCASRejectsParentGenerationChange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newReselectedRetirementFixture(t, "retiring-cancel-generation")
	scheme := deletionTestScheme(t)
	live := f.cluster.DeepCopy()
	live.Generation++
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(live, f.node, f.daemonSet).Build()
	r := f.reconciler(kubeClient, scheme)

	membership, err := evaluateNodeLocalPoolMembership(f.cluster.Spec.Storage.NodeLocalPools, []corev1.Node{*f.node})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err := r.cancelReselectedNodeLocalPoolRetirements(ctx, f.cluster, membership, nil)
	if err != nil || len(cancelled) != 0 {
		t.Fatalf("cancel against a stale parent generation = %v, %v; want no cancellation", cancelled, err)
	}
	claim, _ := f.freshClaim(t, kubeClient)
	if !claim.Retiring {
		t.Fatal("cancellation ignored a parent spec generation change before the durable CAS")
	}
}

func TestReselectedRetirementCancelCASRejectsUnselectedNode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newReselectedRetirementFixture(t, "retiring-cancel-unselected")
	scheme := deletionTestScheme(t)
	// The in-memory snapshot still sees the selector match, but the live Node
	// lost the pool label again before the CAS.
	live := f.node.DeepCopy()
	live.Labels = map[string]string{testStorageOwnerLabelKey: "not-selected"}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(f.cluster, live, f.daemonSet).Build()
	r := f.reconciler(kubeClient, scheme)

	membership, err := evaluateNodeLocalPoolMembership(f.cluster.Spec.Storage.NodeLocalPools, []corev1.Node{*f.node})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err := r.cancelReselectedNodeLocalPoolRetirements(ctx, f.cluster, membership, nil)
	if err != nil || len(cancelled) != 0 {
		t.Fatalf("cancel for a Node that lost its selector = %v, %v; want no cancellation", cancelled, err)
	}
	claim, _ := f.freshClaim(t, kubeClient)
	if !claim.Retiring {
		t.Fatal("cancellation ignored selector removal before the durable CAS")
	}
}
