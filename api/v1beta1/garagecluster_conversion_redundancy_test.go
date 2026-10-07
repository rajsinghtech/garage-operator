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
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// TestConvert_RedundancyStatusRoundTrip: status.redundancy (#474) is served by
// both versions and must survive v1beta2 -> v1beta1 -> v1beta2 unchanged, or
// a v1beta1 client's status write would drop an in-flight proof.
func TestConvert_RedundancyStatusRoundTrip(t *testing.T) {
	at := metav1.NewTime(time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC))
	node := strings.Repeat("a", 64)
	src := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testStoreCR, Namespace: testNS},
		Spec:       v1beta2.GarageClusterSpec{Zone: testZone, Storage: &v1beta2.StorageSpec{Replicas: 3}},
		Status: v1beta2.GarageClusterStatus{Redundancy: &v1beta2.RedundancyStatus{
			Verification: &v1beta2.RedundancyVerificationStatus{
				Phase: v1beta2.RedundancyPhaseSettling, Trigger: v1beta2.RedundancyTriggerRequested,
				StartedAt: &at, PhaseStartedAt: &at, LayoutVersion: 4, TopologyHash: strings.Repeat("d", 64),
				RequestToken: "again", CurrentNodeID: node, CompletedNodeIDs: []string{node},
				Evidence: &v1beta2.RedundancyProofEvidence{
					NodeStage: v1beta2.RedundancyNodeStageBlocks, WorkerBaseline: 9, RepairWorkerID: 10, Launches: 1,
					SyncErrorBaselines: map[string]uint64{node + "/2": 1}, TablesRecheckNodeIDs: []string{node},
					ResyncErrorBaselines: map[string]uint64{node + "/1": 0}, PeerDownSeen: true,
					QuietSince: &at, BlockErrorsBaseline: ptr.To(int64(0)), BlockErrorsBaselineAt: &at,
				},
			},
			DeferredNodes: []v1beta2.RedundancyDeferredNode{{
				NodeID: node, Reason: v1beta2.RedundancyDeferRepairFailed, Since: at,
			}},
			LastProgressAt: &at,
			Nodes: []v1beta2.NodeRedundancyStatus{{
				NodeID: node, Observed: true, ResyncQueueLength: ptr.To(int64(0)), ResyncIdle: ptr.To(true),
				BlockErrors: ptr.To(int32(0)),
			}},
		}},
	}
	down := &GarageCluster{}
	if err := down.ConvertFrom(src); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if down.Status.Redundancy == nil || down.Status.Redundancy.Verification.Phase != RedundancyPhaseSettling {
		t.Fatalf("v1beta1 status.redundancy = %+v", down.Status.Redundancy)
	}
	up := &v1beta2.GarageCluster{}
	if err := down.ConvertTo(up); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if !equality.Semantic.DeepEqual(src.Status.Redundancy, up.Status.Redundancy) {
		t.Fatalf("round trip changed status.redundancy:\nwant %+v\ngot  %+v", src.Status.Redundancy, up.Status.Redundancy)
	}
}
