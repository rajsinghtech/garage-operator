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
	"fmt"
	"sort"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// stagingTestNodeAdmitted mirrors the scheduler's required node matching:
// every nodeSelector entry AND at least one required node-affinity term,
// where an empty term matches no Node.
func stagingTestNodeAdmitted(spec corev1.PodSpec, nodeLabels map[string]string) bool {
	for key, value := range spec.NodeSelector {
		if nodeLabels[key] != value {
			return false
		}
	}
	if spec.Affinity == nil || spec.Affinity.NodeAffinity == nil ||
		spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		return true
	}
	for _, term := range spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms {
		if len(term.MatchExpressions) == 0 && len(term.MatchFields) == 0 {
			continue
		}
		matched := len(term.MatchFields) == 0
		for _, expression := range term.MatchExpressions {
			value, present := nodeLabels[expression.Key]
			switch expression.Operator {
			case corev1.NodeSelectorOpIn:
				found := false
				for _, candidate := range expression.Values {
					found = found || (present && candidate == value)
				}
				matched = matched && found
			case corev1.NodeSelectorOpNotIn:
				for _, candidate := range expression.Values {
					matched = matched && (!present || candidate != value)
				}
			case corev1.NodeSelectorOpExists:
				matched = matched && present
			case corev1.NodeSelectorOpDoesNotExist:
				matched = matched && !present
			default:
				matched = false
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func TestBridgeNodeLocalPoolMembershipSelectorRoundTripsWithoutAliasing(t *testing.T) {
	t.Parallel()
	const activationLabel = "garage.rajsingh.info/activation"
	zone := func(value string) corev1.NodeSelectorTerm {
		return corev1.NodeSelectorTerm{MatchExpressions: []corev1.NodeSelectorRequirement{{
			Key: "example.com/zone", Operator: corev1.NodeSelectorOpIn, Values: []string{value},
		}}}
	}
	preferred := []corev1.PreferredSchedulingTerm{{Weight: 10, Preference: zone("a")}}
	antiAffinity := &corev1.PodAntiAffinity{RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{{
		TopologyKey: "kubernetes.io/hostname",
	}}}
	for _, test := range []struct {
		name     string
		affinity *corev1.Affinity
	}{
		{name: "no user affinity"},
		{name: "user pod anti-affinity only", affinity: &corev1.Affinity{PodAntiAffinity: antiAffinity}},
		{name: "user preferred node affinity only", affinity: &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{PreferredDuringSchedulingIgnoredDuringExecution: preferred},
		}},
		{name: "user required node affinity alternatives", affinity: &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{zone("a"), zone("b")},
				},
				PreferredDuringSchedulingIgnoredDuringExecution: preferred,
			},
			PodAntiAffinity: antiAffinity,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			// userAffinity stands in for the GarageCluster spec object that the
			// DaemonSet builder shares by pointer.
			userAffinity := test.affinity.DeepCopy()
			want := corev1.PodSpec{
				NodeSelector: map[string]string{activationLabel: "old", "example.com/disk": "ssd"},
				Affinity:     test.affinity.DeepCopy(),
			}
			spec := corev1.PodSpec{
				NodeSelector: map[string]string{activationLabel: "old", "example.com/disk": "ssd"},
				Affinity:     userAffinity,
			}
			if err := bridgeNodeLocalPoolMembershipSelector(&spec, activationLabel, "old", "new"); err != nil {
				t.Fatal(err)
			}
			if !equality.Semantic.DeepEqual(userAffinity, test.affinity) {
				t.Fatalf("bridge mutated the shared user affinity in place: %+v", userAffinity)
			}
			for _, value := range []string{"old", "new"} {
				labels := map[string]string{activationLabel: value, "example.com/disk": "ssd", "example.com/zone": "a"}
				if !stagingTestNodeAdmitted(spec, labels) {
					t.Fatalf("bridge does not admit a Node carrying %q", value)
				}
			}
			unbridgeNodeLocalPoolMembershipSelector(&spec, activationLabel, "old")
			if !equality.Semantic.DeepEqual(spec, want) {
				t.Fatalf("unbridge did not restore the exact selector:\n got %+v\nwant %+v", spec, want)
			}
		})
	}
}

const (
	stagingSurvivorA = "staging-worker-a"
	stagingSurvivorB = "staging-worker-b"
	stagingRetiring  = "staging-worker-c"
)

// membershipStagingFixture is one active pool with two surviving members and
// one retiring member (node c), all on the old activation token.
type membershipStagingFixture struct {
	t               *testing.T
	ctx             context.Context
	cluster         *garagev1beta2.GarageCluster
	reconciler      *GarageClusterReconciler
	kubeClient      client.Client
	daemonSetKey    client.ObjectKey
	activationLabel string
	claimKey        string
	oldValue        string
	wantTemplate    corev1.PodSpec
	state           *nodeLocalPoolState
	states          map[string]*nodeLocalPoolState
}

func newMembershipStagingFixture(
	t *testing.T,
	slug string,
	scheme *runtime.Scheme,
	wrap func(client.WithWatch) client.WithWatch,
) *membershipStagingFixture {
	t.Helper()
	cluster := nodeLocalPoolActivationTestCluster("staging-"+slug, "a")
	pool := &cluster.Spec.Storage.NodeLocalPools[0]
	activationLabel := nodeLocalPoolActivationLabel(cluster, pool.Name)
	const oldValue = nodeLocalPoolActivationLabelValue
	claim, err := newNodeLocalPoolHostPathClaim(cluster, pool, "")
	if err != nil {
		t.Fatal(err)
	}
	claimValue, err := encodeNodeLocalPoolHostPathClaim(claim)
	if err != nil {
		t.Fatal(err)
	}
	claimKey := nodeLocalPoolHostPathClaimAnnotation(cluster, pool.Name)
	newNode := func(name string) *corev1.Node {
		return &corev1.Node{ObjectMeta: metav1.ObjectMeta{
			Name: name, UID: types.UID(name + "-uid"),
			Labels:      map[string]string{testStorageOwnerLabelKey: "a", activationLabel: oldValue},
			Annotations: map[string]string{claimKey: claimValue},
		}}
	}
	nodeA, nodeB, nodeC := newNode(stagingSurvivorA), newNode(stagingSurvivorB), newNode(stagingRetiring)
	daemonSet := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: storageDaemonSetName(cluster, pool.Name), Namespace: cluster.Namespace,
			UID: types.UID(cluster.Name + "-daemonset-uid"), Generation: 1,
			Labels: map[string]string{
				labelCluster: cluster.Name, labelTier: tierStorage, labelNodeLocalPool: pool.Name,
			},
			Annotations: map[string]string{annotationNodeLocalPoolActivationValue: oldValue},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
				cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster),
			)},
		},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
				annotationNodeLocalPoolActivationValue: oldValue,
			}},
			Spec: corev1.PodSpec{
				NodeSelector:    map[string]string{activationLabel: oldValue},
				SchedulingGates: []corev1.PodSchedulingGate{{Name: nodeLocalPoolSchedulingGateName}},
			},
		}},
		Status: appsv1.DaemonSetStatus{ObservedGeneration: 1},
	}
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}, &garagev1beta1.GarageNode{}).
		WithObjects(cluster, nodeA, nodeB, nodeC, daemonSet).Build()
	if wrap != nil {
		kubeClient = wrap(kubeClient)
	}
	reconciler := &GarageClusterReconciler{
		Client: kubeClient, APIReader: kubeClient, Scheme: scheme, ClusterScoped: true,
		LayoutMutations: NewLayoutMutationCoordinator(),
	}
	// A settled layout with no roles lets retired-claim cleanup finish.
	reconciler.nodeLocalPoolLayoutGetter = func(context.Context, *garagev1beta2.GarageCluster) (*garage.ClusterLayout, error) {
		return &garage.ClusterLayout{Version: 3}, nil
	}
	reconciler.layoutHistoryGetter = func(context.Context, *garagev1beta2.GarageCluster) (*garage.LayoutHistoryResponse, error) {
		return &garage.LayoutHistoryResponse{
			CurrentVersion: 3, Versions: []garage.LayoutVersion{{Version: 3, Status: garage.LayoutVersionStatusCurrent}},
		}, nil
	}
	state := &nodeLocalPoolState{
		pool: pool, activationLabel: activationLabel, activationValue: oldValue,
		desiredNodes: map[string]*corev1.Node{stagingSurvivorA: nodeA, stagingSurvivorB: nodeB},
	}
	return &membershipStagingFixture{
		t: t, ctx: context.Background(), cluster: cluster, reconciler: reconciler, kubeClient: kubeClient,
		daemonSetKey: client.ObjectKeyFromObject(daemonSet), activationLabel: activationLabel,
		claimKey: claimKey, oldValue: oldValue, wantTemplate: *daemonSet.Spec.Template.Spec.DeepCopy(),
		state: state, states: map[string]*nodeLocalPoolState{pool.Name: state},
	}
}

func (f *membershipStagingFixture) daemonSet() *appsv1.DaemonSet {
	f.t.Helper()
	fresh := &appsv1.DaemonSet{}
	if err := f.kubeClient.Get(f.ctx, f.daemonSetKey, fresh); err != nil {
		f.t.Fatal(err)
	}
	return fresh
}

// node returns nil once the Kubernetes Node is gone.
func (f *membershipStagingFixture) node(name string) *corev1.Node {
	f.t.Helper()
	node := &corev1.Node{}
	if err := f.kubeClient.Get(f.ctx, types.NamespacedName{Name: name}, node); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return nil
		}
		f.t.Fatal(err)
	}
	return node
}

// pass runs one cleanup and then requires every current desired member to
// stay admitted by the published DaemonSet template, whatever the result.
func (f *membershipStagingFixture) pass(label string) (nodeLocalPoolActivationCleanup, error) {
	f.t.Helper()
	result, err := f.reconciler.cleanupNodeLocalPoolActivationState(
		f.ctx, f.cluster, f.states, map[string]*garagev1beta1.GarageNode{},
	)
	template := f.daemonSet().Spec.Template.Spec
	for name := range f.state.desiredNodes {
		node := f.node(name)
		if node != nil && !stagingTestNodeAdmitted(template, node.Labels) {
			f.t.Errorf("%s: surviving Node %s (%s=%q) is no longer admitted by the DaemonSet template %+v",
				label, name, f.activationLabel, node.Labels[f.activationLabel], template)
		}
	}
	return result, err
}

// snapshot renders the DaemonSet fence state and every Node's pool metadata.
func (f *membershipStagingFixture) snapshot() string {
	f.t.Helper()
	daemonSet := f.daemonSet()
	var lines []string
	lines = append(lines, fmt.Sprintf("ds annotations=%v selector=%v affinity=%+v template-token=%s",
		daemonSet.Annotations, daemonSet.Spec.Template.Spec.NodeSelector, daemonSet.Spec.Template.Spec.Affinity,
		daemonSet.Spec.Template.Annotations[annotationNodeLocalPoolActivationValue]))
	for _, name := range []string{stagingSurvivorA, stagingSurvivorB, stagingRetiring} {
		node := f.node(name)
		if node == nil {
			lines = append(lines, name+" absent")
			continue
		}
		_, claimed := node.Annotations[f.claimKey]
		lines = append(lines, fmt.Sprintf("%s token=%q claimed=%v", name, node.Labels[f.activationLabel], claimed))
	}
	sort.Strings(lines[1:])
	return strings.Join(lines, "\n")
}

// TestNodeLocalPoolMembershipStagingUnwindsWhenRetiringSetChanges covers a
// retiring set that changes between staging and commit. The bridge belongs to
// one exact set; without an unwind the pool stays on it forever (Node deleted
// or selected again) or every later reconcile fails (another member retires).
// Surviving members must stay admitted by the DaemonSet template throughout.
func TestNodeLocalPoolMembershipStagingUnwindsWhenRetiringSetChanges(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		slug   string
		change func(f *membershipStagingFixture)
		// stillRetiring lists the Nodes the final committed fence must cover;
		// empty means the bridge must be unwound back to the old selector.
		stillRetiring []string
	}{
		{
			name: "retiring Node deleted",
			slug: "deleted",
			change: func(f *membershipStagingFixture) {
				if err := f.kubeClient.Delete(f.ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: stagingRetiring}}); err != nil {
					f.t.Fatal(err)
				}
			},
		},
		{
			name: "retiring Node selected again",
			slug: "reselected",
			change: func(f *membershipStagingFixture) {
				f.state.desiredNodes[stagingRetiring] = f.node(stagingRetiring)
			},
		},
		{
			name: "another member retires",
			slug: "widened",
			change: func(f *membershipStagingFixture) {
				delete(f.state.desiredNodes, stagingSurvivorB)
			},
			stillRetiring: []string{stagingSurvivorB, stagingRetiring},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newMembershipStagingFixture(t, test.slug, deletionTestScheme(t), nil)
			mustPass := func(label string) nodeLocalPoolActivationCleanup {
				t.Helper()
				result, err := f.pass(label)
				if err != nil {
					t.Fatalf("%s: cleanup failed: %v", label, err)
				}
				return result
			}

			// Stage the bridge for {c}, then move one survivor to the staged token.
			mustPass("stage")
			staged := f.daemonSet()
			stagedTarget := staged.Annotations[annotationNodeLocalPoolMembershipStaging]
			if stagedTarget != nodeLocalPoolMembershipFenceTarget([]string{stagingRetiring}) {
				t.Fatalf("first pass staging = %q, want the exact {%s} target", stagedTarget, stagingRetiring)
			}
			stagedValue := nodeLocalPoolMembershipActivationValue(staged, stagedTarget)
			mustPass("migrate first survivor")
			if got := f.node(stagingSurvivorA).Labels[f.activationLabel]; got != stagedValue {
				t.Fatalf("survivor %s token = %q, want staged %q", stagingSurvivorA, got, stagedValue)
			}

			test.change(f)

			var finalTarget string
			if len(test.stillRetiring) > 0 {
				finalTarget = nodeLocalPoolMembershipFenceTarget(test.stillRetiring)
			}
			for i := 0; ; i++ {
				if i == 12 {
					t.Fatalf("membership transition did not settle; DaemonSet annotations %v", f.daemonSet().Annotations)
				}
				result := mustPass(fmt.Sprintf("pass %d after the retiring set changed", i))
				current := f.daemonSet()
				if current.Annotations[annotationNodeLocalPoolMembershipStaging] != "" {
					continue
				}
				if finalTarget == "" && !result.pending {
					break
				}
				if finalTarget != "" && current.Annotations[annotationNodeLocalPoolMembershipFence] == finalTarget {
					break
				}
			}

			final := f.daemonSet()
			if finalTarget == "" {
				if !equality.Semantic.DeepEqual(final.Spec.Template.Spec, f.wantTemplate) {
					t.Fatalf("unwound template = %+v, want the exact pre-staging template %+v", final.Spec.Template.Spec, f.wantTemplate)
				}
				if final.Annotations[annotationNodeLocalPoolMembershipFence] != "" ||
					nodeLocalPoolActivationValueForDaemonSet(final) != f.oldValue {
					t.Fatalf("unwound DaemonSet committed a fence: %v", final.Annotations)
				}
				for name := range f.state.desiredNodes {
					if got := f.node(name).Labels[f.activationLabel]; got != f.oldValue {
						t.Fatalf("desired Node %s token = %q after unwind, want %q", name, got, f.oldValue)
					}
				}
				return
			}
			committedValue := nodeLocalPoolActivationValueForDaemonSet(final)
			if committedValue == f.oldValue || committedValue == stagedValue ||
				final.Spec.Template.Spec.NodeSelector[f.activationLabel] != committedValue {
				t.Fatalf("fence for the widened retiring set committed token %q (old %q, abandoned %q), selector %v",
					committedValue, f.oldValue, stagedValue, final.Spec.Template.Spec.NodeSelector)
			}
			if got := f.node(stagingSurvivorA).Labels[f.activationLabel]; got != committedValue {
				t.Fatalf("survivor %s token = %q, want committed %q", stagingSurvivorA, got, committedValue)
			}
			if stagingTestNodeAdmitted(final.Spec.Template.Spec, map[string]string{
				testStorageOwnerLabelKey: "a", f.activationLabel: f.oldValue,
			}) {
				t.Fatalf("committed selector still admits retiring Nodes %v on the old token", test.stillRetiring)
			}
		})
	}
}

// TestNodeLocalPoolMembershipTransitionSweepsKubeWriteFaults runs a member
// removal (stage bridge, migrate survivors, commit, release the retired Node)
// with one failed or conflicting Kubernetes write at every position. Every
// pass, faulted or not, must keep both survivors admitted by the DaemonSet
// template, and every run must converge to the uninterrupted end state.
func TestNodeLocalPoolMembershipTransitionSweepsKubeWriteFaults(t *testing.T) {
	sweepFaults(t, faultScenario{
		name: "node-local member removal",
		build: func(t *testing.T, kf *kubeFaults, _ *fakeGarage, scheme *runtime.Scheme) *faultEnv {
			f := newMembershipStagingFixture(t, "fault-sweep", scheme, kf.wrap)
			passes := 0
			return &faultEnv{
				step: func(context.Context) error {
					passes++
					_, err := f.pass(fmt.Sprintf("pass %d", passes))
					return err
				},
				observe: func(context.Context) string { return f.snapshot() },
				done: func(context.Context) bool {
					daemonSet := f.daemonSet()
					retired := f.node(stagingRetiring)
					_, claimed := retired.Annotations[f.claimKey]
					_, labelled := retired.Labels[f.activationLabel]
					return daemonSet.Annotations[annotationNodeLocalPoolMembershipStaging] == "" &&
						daemonSet.Annotations[annotationNodeLocalPoolMembershipFence] ==
							nodeLocalPoolMembershipFenceTarget([]string{stagingRetiring}) &&
						!claimed && !labelled
				},
			}
		},
		maxRetries: 16,
	})
}
