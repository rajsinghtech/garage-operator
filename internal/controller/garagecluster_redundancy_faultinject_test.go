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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// redundancyFaultStep is the simulated time between reconcile passes.
const redundancyFaultStep = 2 * time.Minute

func redundancyFaultObjects() []client.Object {
	objects := []client.Object{&garagev1beta2.GarageCluster{
		// The proof runs only on request (A1); the model's roles carry this UID.
		ObjectMeta: metav1.ObjectMeta{
			Name: fiCluster, Namespace: fiNS, UID: redundancyTestClusterUID,
			Annotations: map[string]string{garagev1beta1.AnnotationVerifyRedundancy: "2026-10-06"},
		},
		Spec: garagev1beta2.GarageClusterSpec{Storage: &garagev1beta2.StorageSpec{}},
		// FullyReplicated must never move Ready (D8): it stays True below.
		Status: garagev1beta2.GarageClusterStatus{Phase: PhaseRunning, Conditions: []metav1.Condition{{
			Type: garagev1beta1.ConditionReady, Status: metav1.ConditionTrue, Reason: "Reconciled",
			LastTransitionTime: metav1.NewTime(time.Date(2026, 10, 6, 11, 0, 0, 0, time.UTC)),
		}}},
	}}
	for i := 0; i < 3; i++ {
		objects = append(objects, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("%s-%d", fiCluster, i), Namespace: fiNS, UID: types.UID(fmt.Sprintf("pod-uid-%d", i)),
				Labels: map[string]string{labelCluster: fiCluster, labelTier: tierStorage},
			},
			Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: defaultAppName}}},
		})
	}
	return objects
}

// redundancyFaultScenario drives the proof through the real status pass:
// the Admin API reads updateStatusFromCluster makes, applyRedundancyStatus
// (layout read, pod list, repair launches) and the single status write.
// Every pass builds a new reconciler, so each one is an operator restart: the
// proof may only continue from what was persisted. The first warmup passes
// run inside build, so the sweep's fault positions cover every proof stage
// (launch, metadata sync, blocks scan, settling), not just the first pass.
func redundancyFaultScenario(name string, warmup int, disrupt func(g *redundancyGarage, pass int, now time.Time)) faultScenario {
	return faultScenario{
		name:       name,
		maxRetries: 30,
		build: func(t *testing.T, kf *kubeFaults, gf *fakeGarage, scheme *runtime.Scheme) *faultEnv {
			model := newRedundancyGarage(3)
			gf.extra = model.serveHTTP
			gf.extraSnapshot = func() string {
				model.mu.Lock()
				defer model.mu.Unlock()
				lines := make([]string, 0, len(model.nodes))
				for _, node := range model.nodes {
					// A Verified proof must rest on a finished table sync and
					// blocks repair on every node, whatever the faults cost.
					lines = append(lines, fmt.Sprintf("node %s syncing=%v repairing=%d synced=%v repaired=%v",
						shortID(node.id), node.syncLeft > 0, len(node.repairLeft), node.syncsDone > 0, node.repairsDone > 0))
				}
				return strings.Join(lines, "\n")
			}
			c := newFaultKube(t, kf, scheme, redundancyFaultObjects()...)
			key := types.NamespacedName{Namespace: fiNS, Name: fiCluster}
			now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
			pass := 0
			step := func(ctx context.Context) error {
				pass++
				defer func() {
					now = now.Add(redundancyFaultStep)
					model.tick(now)
					if disrupt != nil {
						disrupt(model, pass, now)
					}
				}()
				r := &GarageClusterReconciler{
					Client:                 c,
					Scheme:                 scheme,
					redundancyClock:        func() time.Time { return now },
					blockResyncQuietPeriod: 5 * time.Minute,
				}
				cluster := &garagev1beta2.GarageCluster{}
				if err := c.Get(ctx, key, cluster); err != nil {
					return err
				}
				gc := garage.NewClient(gf.url(), "test-token")
				var responses redundancyResponses
				health, healthErr := gc.GetClusterHealth(ctx)
				if healthErr == nil {
					responses.Health = health
				}
				if status, err := gc.GetClusterStatus(ctx); err == nil {
					responses.Status = status
				}
				if history, err := gc.GetClusterLayoutHistory(ctx); err == nil {
					responses.History = history
				}
				if healthErr == nil {
					responses.Workers, responses.BlockErrors = observeBlockResyncStatus(
						ctx, gc, &cluster.Status, now, capacitylessGatewayNodeIDs(responses.Status))
				}
				base := redundancyStatusSnapshot(cluster)
				r.applyRedundancyStatus(ctx, cluster, gc, responses)
				return writeComputedClusterStatus(ctx, r.Client, cluster, base)
			}
			get := func(ctx context.Context) *garagev1beta2.GarageCluster {
				cluster := &garagev1beta2.GarageCluster{}
				if err := c.Get(ctx, key, cluster); err != nil {
					t.Fatal(err)
				}
				return cluster
			}
			for i := 0; i < warmup; i++ {
				_ = step(context.Background())
			}
			return &faultEnv{
				step: step,
				done: func(ctx context.Context) bool {
					conditions := get(ctx).Status.Conditions
					if !meta.IsStatusConditionTrue(conditions, garagev1beta1.ConditionReady) {
						t.Errorf("the redundancy proof changed Ready: %+v", conditions)
					}
					return meta.IsStatusConditionTrue(conditions, garagev1beta1.ConditionFullyReplicated)
				},
				observe: func(ctx context.Context) string {
					return renderRedundancyForFaults(get(ctx))
				},
			}
		},
	}
}

// renderRedundancyForFaults renders the persisted proof without timestamps,
// which legitimately depend on how many passes a fault cost.
func renderRedundancyForFaults(cluster *garagev1beta2.GarageCluster) string {
	var lines []string
	if ready := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionReady); ready != nil {
		lines = append(lines, fmt.Sprintf("ready %s/%s %s", ready.Status, ready.Reason, ready.LastTransitionTime.UTC().Format(time.RFC3339)))
	}
	if condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionFullyReplicated); condition != nil {
		lines = append(lines, fmt.Sprintf("condition %s/%s %q gen=%d", condition.Status, condition.Reason, condition.Message, condition.ObservedGeneration))
	}
	redundancy := cluster.Status.Redundancy
	if redundancy == nil {
		return strings.Join(append(lines, "redundancy <nil>"), "\n")
	}
	if v := redundancy.Verification; v != nil {
		lines = append(lines, fmt.Sprintf("verification phase=%s trigger=%s layout=%d topology=%v token=%q verified=%v evidence=%v current=%q completed=%d",
			v.Phase, v.Trigger, v.LayoutVersion, v.TopologyHash != "", v.RequestToken, v.VerifiedAt != nil, v.Evidence != nil,
			shortID(v.CurrentNodeID), len(v.CompletedNodeIDs)))
	}
	for _, node := range redundancy.DeferredNodes {
		lines = append(lines, fmt.Sprintf("deferred %s %s", shortID(node.NodeID), node.Reason))
	}
	for _, node := range redundancy.Nodes {
		lines = append(lines, fmt.Sprintf("node %s observed=%v queue=%v idle=%v errors=%v partitions=%v metadataQueue=%v progress=%q",
			shortID(node.NodeID), node.Observed, derefInt64(node.ResyncQueueLength), derefBool(node.ResyncIdle),
			derefInt32(node.BlockErrors), derefInt32(node.MetadataSyncPartitions), derefInt64(node.MetadataQueueLength), node.BlockRepairProgress))
	}
	return strings.Join(lines, "\n")
}

func derefInt64(v *int64) string {
	if v == nil {
		return "-"
	}
	return fmt.Sprint(*v)
}

func derefInt32(v *int32) string {
	if v == nil {
		return "-"
	}
	return fmt.Sprint(*v)
}

func derefBool(v *bool) string {
	if v == nil {
		return "-"
	}
	return fmt.Sprint(*v)
}

func TestFaultInjectionRedundancyProof(t *testing.T) {
	// Warm up into the settling stage so faults land in every proof stage.
	sweepFaults(t, redundancyFaultScenario("redundancy proof", 5, nil))
}

// TestFaultInjectionRedundancyProofDoubleFaults interrupts the recovery from
// a first fault with a second one, like sweepDoubleFaults, but bounds the
// positions to those that can fire: the first fault within the warmup and
// first pass, the second within the single retry pass that follows. The
// unbounded sweep spends almost all of its time on positions that never fire.
func TestFaultInjectionRedundancyProofDoubleFaults(t *testing.T) {
	sc := redundancyFaultScenario("redundancy proof", 3, nil)
	t.Cleanup(resetBucketQuotaMetricsForFaultTests)
	base := runFaultFlow(t, sc, 0, kubeFaultError, nil)
	if !base.converged {
		t.Fatalf("baseline did not converge: %v", base.lastErr)
	}
	// Measure how many calls and writes the warmup plus first pass make, and
	// the most one retry pass makes.
	kf, gf := &kubeFaults{}, newFakeGarage(t)
	env := sc.build(t, kf, gf, testSchemeForFault(t))
	_ = env.step(context.Background())
	firstCalls, firstWrites := gf.calls, kf.writes
	retryCalls, retryWrites := 0, 0
	for i := 0; i < 12; i++ {
		calls, writes := gf.calls, kf.writes
		_ = env.step(context.Background())
		retryCalls, retryWrites = max(retryCalls, gf.calls-calls), max(retryWrites, kf.writes-writes)
	}
	check := func(label string, got runResult) {
		t.Helper()
		switch {
		case !got.converged:
			t.Errorf("[%s]: did not converge: %v", label, got.lastErr)
		case got.garageSnap != base.garageSnap:
			t.Errorf("[%s]: Garage end state diverged\n--- baseline\n%s\n--- faulted\n%s", label, base.garageSnap, got.garageSnap)
		case got.kubeSnap != base.kubeSnap:
			t.Errorf("[%s]: Kubernetes end state diverged\n--- baseline\n%s\n--- faulted\n%s", label, base.kubeSnap, got.kubeSnap)
		case got.steadyObjWrites != 0 || got.steadyMutations != 0:
			t.Errorf("[%s]: converged state is not quiet", label)
		}
	}
	runs := 0
	for i := 1; i <= firstCalls; i++ {
		for j := 1; j <= retryWrites; j++ {
			res := runFaultFlow(t, sc, 0, kubeFaultError, &garageFault{At: i, AfterCommit: true},
				func(kf *kubeFaults, _ *fakeGarage) {
					kf.mu.Lock()
					kf.failAt, kf.kind, kf.hit = kf.writes+j, kubeFaultError, false
					kf.mu.Unlock()
				})
			if res.garageFaultHit && res.kubeFaultHit {
				runs++
				check(fmt.Sprintf("garage #%d lost response, then kube retry write #%d fails", i, j), res)
			}
		}
	}
	for i := 1; i <= firstWrites; i++ {
		for j := 1; j <= retryCalls; j++ {
			for _, after := range []bool{false, true} {
				res := runFaultFlow(t, sc, i, kubeFaultError, nil, func(_ *kubeFaults, gf *fakeGarage) {
					gf.mu.Lock()
					gf.fault, gf.faultHit = &garageFault{At: gf.calls + j, AfterCommit: after}, false
					gf.mu.Unlock()
				})
				if res.kubeFaultHit && res.garageFaultHit {
					runs++
					check(fmt.Sprintf("kube write #%d fails, then retry garage call #%d fails (afterCommit=%v)", i, j, after), res)
				}
			}
		}
	}
	t.Logf("double-fault combinations exercised: %d", runs)
	if runs == 0 {
		t.Fatal("no double-fault combination fired")
	}
}

func TestFaultInjectionRedundancyProofGarageRestart(t *testing.T) {
	// A storage node's Garage process restarts after the metadata launch and
	// again during the blocks scan.
	sweepFaults(t, redundancyFaultScenario("redundancy proof with Garage restarts", 5,
		func(g *redundancyGarage, pass int, now time.Time) {
			switch pass {
			case 1:
				g.restart(0, now)
			case 4:
				g.restart(2, now)
			}
		}))
}
