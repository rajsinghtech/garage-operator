package controller

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// reselectedRetirementScenario drives #470 through the fault harness: every
// pass runs the lifecycle preflight (which may cancel the persisted
// retirement) and then the ordinary recovery activation for a desired Node.
// Any interrupted Node write must converge to the same re-enrolled identity
// and then stay quiet.
func reselectedRetirementScenario() faultScenario {
	return faultScenario{
		name: "node-local reselected retirement cancel + recovery activation",
		build: func(t *testing.T, kf *kubeFaults, _ *fakeGarage, scheme *runtime.Scheme) *faultEnv {
			f := newReselectedRetirementFixture(t, "fi-retiring-rejoin")
			base := fake.NewClientBuilder().WithScheme(scheme).
				WithObjects(f.cluster, f.node, f.daemonSet).Build()
			c := kf.wrap(base)
			r := f.reconciler(c, scheme)
			readNode := func(ctx context.Context) (*corev1.Node, *nodeLocalPoolHostPathClaim, error) {
				node := &corev1.Node{}
				if err := base.Get(ctx, client.ObjectKeyFromObject(f.node), node); err != nil {
					return nil, nil, err
				}
				claim, err := decodeNodeLocalPoolHostPathClaim(node.Annotations[f.claimKey])
				return node, claim, err
			}
			return &faultEnv{
				step: func(ctx context.Context) error {
					transition := f.transition(r)
					result := transition.preflight()
					if result.Err != nil || result.Stop {
						return fmt.Errorf("preflight: stop=%v err=%v", result.Stop, result.Err)
					}
					for nodeName, node := range transition.states[f.pool.Name].desiredNodes {
						if node.Labels[f.label] == nodeLocalPoolActivationLabelValue {
							continue
						}
						if err := r.ensureNodeLocalPoolActivation(
							ctx, f.cluster, f.pool, node, f.label, nodeLocalPoolActivationLabelValue,
							f.recovery, node.Annotations[f.recovery],
						); err != nil {
							return fmt.Errorf("activating %s: %w", nodeName, err)
						}
					}
					return nil
				},
				done: func(ctx context.Context) bool {
					node, claim, err := readNode(ctx)
					return err == nil && !claim.Retiring && node.Labels[f.label] == nodeLocalPoolActivationLabelValue
				},
				observe: func(ctx context.Context) string {
					node, claim, err := readNode(ctx)
					if err != nil {
						return "error: " + err.Error()
					}
					return fmt.Sprintf("label=%q retiring=%v claimID=%s pin=%s paths=%v",
						node.Labels[f.label], claim.Retiring, shortID(claim.GarageNodeID),
						shortID(node.Annotations[f.recovery]), claim.HostPaths)
				},
			}
		},
	}
}

func TestFaultSweep_ReselectedRetiringNodeRejoins(t *testing.T) {
	sweepFaults(t, reselectedRetirementScenario())
}
