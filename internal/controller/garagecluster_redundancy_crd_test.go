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
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// These specs push status.redundancy (#474) through the real generated CRD:
// a complete in-flight proof must be accepted and the enums, minimum, node ID
// pattern and list-map key enforced. envtest has no conversion webhook; the
// v1beta1 round trip is covered in api/v1beta1.
var _ = Describe("GarageCluster status.redundancy CRD validation", func() {
	nodeA := strings.Repeat("a", 64)
	nodeB := strings.Repeat("b", 64)
	now := metav1.Now()

	newCluster := func(name string) *garagev1beta2.GarageCluster {
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Spec: garagev1beta2.GarageClusterSpec{
				Zone: "us-east",
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
				},
				Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
			},
		}
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, cluster) })
		return cluster
	}
	inFlight := func() *garagev1beta2.RedundancyStatus {
		return &garagev1beta2.RedundancyStatus{
			Verification: &garagev1beta2.RedundancyVerificationStatus{
				Phase:            garagev1beta2.RedundancyPhaseScanningBlocks,
				Trigger:          garagev1beta2.RedundancyTriggerLayoutChanged,
				StartedAt:        &now,
				PhaseStartedAt:   &now,
				VerifiedAt:       &now,
				LayoutVersion:    7,
				TopologyHash:     strings.Repeat("c", 64),
				RequestToken:     "2026-10-06",
				CurrentNodeID:    nodeA,
				CompletedNodeIDs: []string{nodeB},
				Evidence: &garagev1beta2.RedundancyProofEvidence{
					SkipTables:            true,
					NodeStage:             garagev1beta2.RedundancyNodeStageBlocks,
					StageLaunchedAt:       &now,
					WorkerBaseline:        22,
					SyncErrorBaselines:    map[string]uint64{nodeA + "/2": 0},
					IdleSince:             &now,
					PeerDownSeen:          true,
					RepairWorkerID:        23,
					Launches:              2,
					PauseUntil:            &now,
					TablesRecheckNodeIDs:  []string{nodeB},
					ResyncErrorBaselines:  map[string]uint64{nodeA + "/1": 0},
					QuietSince:            &now,
					BlockErrorsBaseline:   ptr.To(int64(0)),
					BlockErrorsBaselineAt: &now,
				},
			},
			ProgressObservedAt: &now,
			LastProgressAt:     &now,
			Nodes: []garagev1beta2.NodeRedundancyStatus{
				{NodeID: nodeA, Observed: true, ResyncQueueLength: ptr.To(int64(12)), ResyncIdle: ptr.To(false),
					BlockErrors: ptr.To(int32(0)), MetadataSyncPartitions: ptr.To(int32(0)),
					MetadataQueueLength: ptr.To(int64(0)), BlockRepairProgress: "41.20%"},
				{NodeID: nodeB, Observed: false},
			},
			DeferredNodes: []garagev1beta2.RedundancyDeferredNode{
				{NodeID: nodeB, Reason: garagev1beta2.RedundancyDeferDown, Since: now, RetryAfter: &now},
			},
		}
	}

	It("accepts a complete in-flight proof", func() {
		cluster := newCluster("redundancy-accept")
		cluster.Status.Redundancy = inFlight()
		cluster.Status.Conditions = []metav1.Condition{{
			Type: garagev1beta1.ConditionFullyReplicated, Status: metav1.ConditionFalse,
			Reason: garagev1beta1.ReasonRedundancyVerifying, Message: "Scanning blocks", LastTransitionTime: now,
		}}
		Expect(k8sClient.Status().Update(ctx, cluster)).To(Succeed())

		key := types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}
		stored := &garagev1beta2.GarageCluster{}
		Expect(k8sClient.Get(ctx, key, stored)).To(Succeed())
		Expect(stored.Status.Redundancy.Verification.Evidence.RepairWorkerID).To(Equal(uint64(23)))
		Expect(stored.Status.Redundancy.Verification.CurrentNodeID).To(Equal(nodeA))
		Expect(stored.Status.Redundancy.DeferredNodes).To(HaveLen(1))
		Expect(stored.Status.Redundancy.DeferredNodes[0].Reason).To(Equal(garagev1beta2.RedundancyDeferDown))
		Expect(stored.Status.Redundancy.Nodes).To(HaveLen(2))
		Expect(stored.Status.Redundancy.Nodes[0].BlockRepairProgress).To(Equal("41.20%"))
		Expect(stored.Status.Redundancy.Verification.LayoutVersion).To(Equal(int64(7)))
	})

	DescribeTable("rejects invalid status.redundancy",
		func(mutate func(*garagev1beta2.RedundancyStatus), want string) {
			cluster := newCluster("redundancy-reject-" + strings.ToLower(strings.ReplaceAll(want, ".", "-")))
			cluster.Status.Redundancy = inFlight()
			mutate(cluster.Status.Redundancy)
			err := k8sClient.Status().Update(ctx, cluster)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(want))
		},
		Entry("unknown phase", func(s *garagev1beta2.RedundancyStatus) { s.Verification.Phase = "Done" }, "phase"),
		Entry("unknown trigger", func(s *garagev1beta2.RedundancyStatus) { s.Verification.Trigger = "Manual" }, "trigger"),
		Entry("negative layout version", func(s *garagev1beta2.RedundancyStatus) { s.Verification.LayoutVersion = -1 }, "layoutVersion"),
		Entry("short node ID", func(s *garagev1beta2.RedundancyStatus) { s.Nodes[0].NodeID = "abc" }, "nodeId"),
		Entry("duplicate node ID", func(s *garagev1beta2.RedundancyStatus) { s.Nodes[1].NodeID = s.Nodes[0].NodeID }, "Duplicate"),
		Entry("removed Initial trigger", func(s *garagev1beta2.RedundancyStatus) { s.Verification.Trigger = "Initial" }, "trigger"),
		Entry("unknown defer reason", func(s *garagev1beta2.RedundancyStatus) { s.DeferredNodes[0].Reason = "Gone" }, "reason"),
		Entry("short current node ID", func(s *garagev1beta2.RedundancyStatus) { s.Verification.CurrentNodeID = "abc" }, "currentNodeId"),
		Entry("too many launches", func(s *garagev1beta2.RedundancyStatus) { s.Verification.Evidence.Launches = 4 }, "launches"),
		Entry("unknown node stage", func(s *garagev1beta2.RedundancyStatus) { s.Verification.Evidence.NodeStage = "Scrub" }, "nodeStage"),
	)
})
