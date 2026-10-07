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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// redundancyEnvSite runs the real redundancy status pass (#474) against the
// envtest API server: Garage is the model behind an HTTP server, status is
// read from and written to the API server every pass, and the reconciler
// keeps no state of its own, so a new reconciler resumes from status.
type redundancyEnvSite struct {
	g      *redundancyGarage
	client *garage.Client
	key    types.NamespacedName
	now    time.Time
	r      *GarageClusterReconciler
}

func newRedundancyEnvSite(name string, nodes int, mutate func(*garagev1beta2.GarageCluster)) *redundancyEnvSite {
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec: garagev1beta2.GarageClusterSpec{
			Zone: "us-east",
			Storage: &garagev1beta2.StorageSpec{
				Replicas: int32(nodes),
				Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
				Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
			},
			Replication: &garagev1beta2.ReplicationConfig{Factor: 3},
		},
	}
	if mutate != nil {
		mutate(cluster)
	}
	Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
	DeferCleanup(func() { _ = k8sClient.Delete(ctx, cluster) })

	g := newRedundancyGarage(nodes)
	for _, node := range g.nodes {
		node.owner = string(cluster.UID)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		code, body, ok := g.serveHTTP(request)
		if !ok {
			http.NotFound(w, request)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(body)
	}))
	DeferCleanup(server.Close)
	site := &redundancyEnvSite{
		g:      g,
		client: garage.NewClient(server.URL, "t"),
		key:    types.NamespacedName{Name: name, Namespace: testNamespace},
		now:    time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC),
	}
	site.newReconciler()
	return site
}

// newReconciler replaces the reconciler, as an operator restart does.
func (s *redundancyEnvSite) newReconciler() {
	s.r = &GarageClusterReconciler{
		Client:                 k8sClient,
		Scheme:                 k8sClient.Scheme(),
		blockResyncQuietPeriod: 5 * time.Minute,
		redundancyClock:        func() time.Time { return s.now },
	}
}

func (s *redundancyEnvSite) get() *garagev1beta2.GarageCluster {
	cluster := &garagev1beta2.GarageCluster{}
	Expect(k8sClient.Get(ctx, s.key, cluster)).To(Succeed())
	return cluster
}

// pass is one status pass: observe Garage, advance the proof, write status.
func (s *redundancyEnvSite) pass() *garagev1beta2.GarageCluster {
	cluster := s.get()
	base := redundancyStatusSnapshot(cluster)
	var responses redundancyResponses
	var err error
	responses.Health, err = s.client.GetClusterHealth(ctx)
	Expect(err).NotTo(HaveOccurred())
	responses.Status, err = s.client.GetClusterStatus(ctx)
	Expect(err).NotTo(HaveOccurred())
	responses.History, err = s.client.GetClusterLayoutHistory(ctx)
	Expect(err).NotTo(HaveOccurred())
	responses.Workers, responses.BlockErrors = observeBlockResyncStatus(ctx, s.client, &cluster.Status, s.now, nil)
	s.r.applyRedundancyStatus(ctx, cluster, s.client, responses)
	Expect(writeComputedClusterStatus(ctx, k8sClient, cluster, base)).To(Succeed())
	s.now = s.now.Add(30 * time.Second)
	s.g.tick(s.now)
	return s.get()
}

func (s *redundancyEnvSite) condition(cluster *garagev1beta2.GarageCluster) metav1.Condition {
	condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionFullyReplicated)
	Expect(condition).NotTo(BeNil())
	return *condition
}

// runUntil runs passes until done holds for the persisted cluster.
func (s *redundancyEnvSite) runUntil(max int, done func(*garagev1beta2.GarageCluster) bool) *garagev1beta2.GarageCluster {
	for i := 0; i < max; i++ {
		if cluster := s.pass(); done(cluster) {
			return cluster
		}
	}
	cluster := s.get()
	Fail("redundancy proof did not reach the expected state; condition: " + s.condition(cluster).Reason + " " + s.condition(cluster).Message)
	return nil
}

func (s *redundancyEnvSite) reasonIs(reason string) func(*garagev1beta2.GarageCluster) bool {
	return func(cluster *garagev1beta2.GarageCluster) bool { return s.condition(cluster).Reason == reason }
}

func (s *redundancyEnvSite) request(token string) {
	cluster := s.get()
	patch := []byte(`{"metadata":{"annotations":{"` + garagev1beta1.AnnotationVerifyRedundancy + `":"` + token + `"}}}`)
	Expect(k8sClient.Patch(ctx, cluster, client.RawPatch(types.MergePatchType, patch))).To(Succeed())
}

// declareNodes creates this cluster's GarageNodes: a local (non-external)
// one with a discovered status.nodeId for each local model node, and an
// external one for each external model node. Federated sites decide
// locality only from these objects.
func (s *redundancyEnvSite) declareNodes(local, external []*redundancyGarageNode) {
	capacity := resource.MustParse("1Gi")
	create := func(name string, spec garagev1beta1.GarageNodeSpec, statusID string) {
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Spec:       spec,
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, node) })
		if statusID != "" {
			node.Status.NodeID = statusID
			Expect(k8sClient.Status().Update(ctx, node)).To(Succeed())
		}
	}
	for i, node := range local {
		create(fmt.Sprintf("%s-local-%d", s.key.Name, i), garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: s.key.Name}, Zone: "z1", Capacity: &capacity,
			Storage: &garagev1beta1.NodeStorageConfig{
				Metadata: &garagev1beta1.NodeVolumeConfig{Size: ptr.To(resource.MustParse("1Gi"))},
				Data:     &garagev1beta1.NodeVolumeConfig{Size: ptr.To(resource.MustParse("1Gi"))},
			},
		}, node.id)
	}
	for i, node := range external {
		create(fmt.Sprintf("%s-external-%d", s.key.Name, i), garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: s.key.Name}, Zone: "z2", Capacity: &capacity,
			NodeID:   node.id,
			External: &garagev1beta1.ExternalNodeConfig{Address: "remote.example.net", Port: 3901},
		}, "")
	}
}

// launches is the number of repairs launched so far.
func (s *redundancyEnvSite) launches() int {
	tables, blocks := s.g.totalLaunches()
	return tables + blocks
}

var _ = Describe("GarageCluster FullyReplicated upgrade-safe proof (#474)", func() {
	It("A1: records a baseline on upgrade and starts nothing until requested", func() {
		site := newRedundancyEnvSite("redundancy-a1", 3, nil)
		for i := 0; i < 6; i++ {
			site.pass()
		}
		// Rolling Garage restarts are not a trigger either.
		site.g.restart(0, site.now)
		for i := 0; i < 4; i++ {
			site.pass()
		}
		cluster := site.get()
		condition := site.condition(cluster)
		Expect(condition.Status).To(Equal(metav1.ConditionUnknown))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonRedundancyNotVerified))
		Expect(cluster.Status.Redundancy.Verification.Phase).To(Equal(garagev1beta2.RedundancyPhaseIdle))
		Expect(cluster.Status.Redundancy.Verification.TopologyHash).To(HaveLen(64))
		Expect(site.launches()).To(BeZero())

		site.request("2026-10-06")
		cluster = site.runUntil(80, site.reasonIs(garagev1beta1.ReasonRedundancyVerified))
		Expect(cluster.Status.Redundancy.Verification.Trigger).To(Equal(garagev1beta2.RedundancyTriggerRequested))
		Expect(cluster.Status.Redundancy.Verification.RequestToken).To(Equal("2026-10-06"))
		for _, node := range site.g.nodes {
			Expect(site.g.tablesLaunches[node.id]).To(Equal(1))
			Expect(site.g.blocksLaunches[node.id]).To(Equal(1))
		}
		// The handled token starts nothing more.
		for i := 0; i < 6; i++ {
			site.pass()
		}
		Expect(site.launches()).To(Equal(6))
	})

	It("A2: repairs one storage node at a time and resumes after an operator restart", func() {
		site := newRedundancyEnvSite("redundancy-a2", 3, func(cluster *garagev1beta2.GarageCluster) {
			cluster.Annotations = map[string]string{garagev1beta1.AnnotationVerifyRedundancy: "go"}
		})
		second := site.g.nodes[1].id
		cluster := site.runUntil(40, func(cluster *garagev1beta2.GarageCluster) bool {
			v := cluster.Status.Redundancy.Verification
			return v != nil && v.CurrentNodeID == second && v.Evidence != nil &&
				v.Evidence.NodeStage == garagev1beta2.RedundancyNodeStageBlocks
		})
		Expect(cluster.Status.Redundancy.Verification.CompletedNodeIDs).To(Equal([]string{site.g.nodes[0].id}))
		Expect(site.g.tablesLaunches[site.g.nodes[2].id] + site.g.blocksLaunches[site.g.nodes[2].id]).To(BeZero())

		site.newReconciler()
		site.runUntil(80, site.reasonIs(garagev1beta1.ReasonRedundancyVerified))
		Expect(site.g.maxConcurrent).To(Equal(1))
		want := make([]string, 0, 2*len(site.g.nodes))
		for _, node := range site.g.nodes {
			want = append(want, shortID(node.id)+":tables", shortID(node.id)+":blocks")
			Expect(site.g.tablesLaunches[node.id]).To(Equal(1), "no node is repaired twice after the restart")
		}
		Expect(site.g.launchLog).To(Equal(want))
	})

	It("A3/B2: a federated site without siteRole runs nothing; the writer covers only its local nodes", func() {
		unset := newRedundancyEnvSite("redundancy-a3-unset", 2, func(cluster *garagev1beta2.GarageCluster) {
			cluster.Annotations = map[string]string{garagev1beta1.AnnotationVerifyRedundancy: "go"}
		})
		unset.g.addNode("other-site-uid")
		for i := 0; i < 6; i++ {
			unset.pass()
		}
		cluster := unset.get()
		condition := unset.condition(cluster)
		Expect(condition.Status).To(Equal(metav1.ConditionUnknown))
		Expect(condition.Reason).To(Equal(garagev1beta1.ReasonRedundancySiteRoleUnset))
		Expect(cluster.Status.Redundancy.Verification).To(BeNil())
		Expect(cluster.Status.Redundancy.Scope).To(BeEmpty())
		Expect(unset.launches()).To(Equal(0))

		writer := newRedundancyEnvSite("redundancy-a3-writer", 2, func(cluster *garagev1beta2.GarageCluster) {
			cluster.Annotations = map[string]string{garagev1beta1.AnnotationVerifyRedundancy: "go"}
			cluster.Spec.LayoutManagement = &garagev1beta2.LayoutManagementConfig{SiteRole: garagev1beta2.LayoutSiteRoleWriter}
		})
		// The follower's node carries the writer's own UID tag (the writer
		// declared it as an external GarageNode); a third site's node carries
		// its own UID.
		followerNode := writer.g.addNode(string(writer.get().UID))
		otherSite := writer.g.addNode("other-site-uid")
		writer.declareNodes(writer.g.nodes[:2], []*redundancyGarageNode{followerNode})
		cluster = writer.runUntil(160, writer.reasonIs(garagev1beta1.ReasonRedundancyVerifiedLocal))
		Expect(writer.condition(cluster).Status).To(Equal(metav1.ConditionTrue))
		Expect(writer.condition(cluster).Message).To(ContainSubstring("2/4 federated storage nodes verified (writer-local)"))
		for _, remote := range []*redundancyGarageNode{followerNode, otherSite} {
			Expect(writer.g.tablesLaunches[remote.id] + writer.g.blocksLaunches[remote.id]).To(BeZero())
		}
		Expect(cluster.Status.Redundancy.Verification.CompletedNodeIDs).To(ConsistOf(writer.g.nodes[0].id, writer.g.nodes[1].id))
		Expect(cluster.Status.Redundancy.Scope).To(Equal(garagev1beta2.RedundancyScopeLocal))
		Expect(*cluster.Status.Redundancy.StorageNodes).To(Equal(garagev1beta2.RedundancyStorageNodeCounts{Total: 4, Local: 2, Remote: 2, Verified: 2}))
		Expect(cluster.Status.Redundancy.Coordination).NotTo(BeNil())
	})

	It("B1: topology proofs are off by default and opt-in through onTopologyChange", func() {
		site := newRedundancyEnvSite("redundancy-b1", 3, func(cluster *garagev1beta2.GarageCluster) {
			cluster.Annotations = map[string]string{garagev1beta1.AnnotationVerifyRedundancy: "go"}
		})
		site.runUntil(80, site.reasonIs(garagev1beta1.ReasonRedundancyVerified))
		before := site.launches()

		site.g.addNode(string(site.get().UID))
		cluster := site.runUntil(4, site.reasonIs(garagev1beta1.ReasonRedundancyNotVerified))
		Expect(cluster.Status.Redundancy.Verification.Phase).To(Equal(garagev1beta2.RedundancyPhaseIdle))
		for i := 0; i < 10; i++ {
			site.pass()
		}
		Expect(site.launches()).To(Equal(before), "no repair without the flag")

		cluster = site.get()
		patch := []byte(`{"spec":{"layoutManagement":{"redundancyVerification":{"onTopologyChange":true}}}}`)
		Expect(k8sClient.Patch(ctx, cluster, client.RawPatch(types.MergePatchType, patch))).To(Succeed())
		added := site.g.addNode(string(site.get().UID))
		cluster = site.runUntil(4, func(cluster *garagev1beta2.GarageCluster) bool {
			return cluster.Status.Redundancy.Verification.Trigger == garagev1beta2.RedundancyTriggerNodeChanged
		})
		site.runUntil(120, site.reasonIs(garagev1beta1.ReasonRedundancyVerified))
		Expect(site.g.blocksLaunches[added.id]).To(Equal(1))
		Expect(site.g.tablesLaunches[added.id]).To(BeZero(), "topology proofs scan blocks only")
		Expect(site.g.maxConcurrent).To(Equal(1))
	})

	It("B2: a follower verifies only its own nodes, and only on request", func() {
		site := newRedundancyEnvSite("redundancy-b2", 2, func(cluster *garagev1beta2.GarageCluster) {
			cluster.Spec.LayoutManagement = &garagev1beta2.LayoutManagementConfig{
				SiteRole:               garagev1beta2.LayoutSiteRoleFollower,
				RedundancyVerification: &garagev1beta2.RedundancyVerificationConfig{OnTopologyChange: true},
			}
			cluster.Spec.RemoteClusters = []garagev1beta2.RemoteClusterConfig{{
				Name: "garage-writer", Zone: "z2",
				Connection: garagev1beta2.RemoteClusterConnection{AdminAPIEndpoint: "https://writer.example.net:3903"},
			}}
		})
		// The writer declared every role, so all carry its UID tag.
		site.g.mu.Lock()
		for _, node := range site.g.nodes {
			node.owner = "writer-uid"
		}
		site.g.mu.Unlock()
		writerNode := site.g.addNode("writer-uid")
		site.declareNodes(site.g.nodes[:2], nil)
		for i := 0; i < 6; i++ {
			site.pass()
		}
		// A topology change starts nothing on a follower, even with the flag.
		site.g.addNode("writer-uid")
		for i := 0; i < 6; i++ {
			site.pass()
		}
		cluster := site.get()
		Expect(site.condition(cluster).Reason).To(Equal(garagev1beta1.ReasonRedundancyNotVerified))
		Expect(site.condition(cluster).Message).To(ContainSubstring("verifies only the 2 storage nodes that run here"))
		Expect(site.launches()).To(BeZero())

		site.request("follower-1")
		cluster = site.runUntil(200, site.reasonIs(garagev1beta1.ReasonRedundancyVerifiedLocal))
		Expect(site.condition(cluster).Message).To(ContainSubstring("2/4 federated storage nodes verified (follower-local)"))
		Expect(site.g.tablesLaunches[writerNode.id] + site.g.blocksLaunches[writerNode.id]).To(BeZero())
		for _, node := range site.g.nodes[:2] {
			Expect(site.g.tablesLaunches[node.id]).To(Equal(1))
			Expect(site.g.blocksLaunches[node.id]).To(Equal(1))
		}
		Expect(site.g.maxConcurrent).To(Equal(1))
	})

	It("B3: a requested site waits while another site's blocks repair runs", func() {
		site := newRedundancyEnvSite("redundancy-b3", 2, func(cluster *garagev1beta2.GarageCluster) {
			cluster.Spec.LayoutManagement = &garagev1beta2.LayoutManagementConfig{SiteRole: garagev1beta2.LayoutSiteRoleWriter}
		})
		remote := site.g.addNode("other-site-uid")
		site.declareNodes(site.g.nodes[:2], nil)
		site.pass()
		site.now = site.now.Add(time.Hour) // past the first-pass hold-down
		site.g.mu.Lock()
		site.g.repairTicks = 20
		site.g.mu.Unlock()
		Expect(site.g.launch(remote.id, "blocks")).To(Succeed())
		site.request("go")
		cluster := site.pass()
		Expect(site.condition(cluster).Reason).To(Equal(garagev1beta1.ReasonRedundancyWaitingForOtherSite))
		Expect(cluster.Status.Redundancy.Verification.Phase).To(Equal(garagev1beta2.RedundancyPhasePending))
		Expect(cluster.Status.Redundancy.Coordination.LastRemoteRepairNodeID).To(Equal(remote.id))
		site.g.mu.Lock()
		site.g.repairTicks = 1
		site.g.mu.Unlock()
		for i := 0; i < 20; i++ { // the remote repair still runs for most of this
			site.pass()
		}
		Expect(site.launches()).To(Equal(1), "only the remote repair ran")
		cluster = site.runUntil(200, func(*garagev1beta2.GarageCluster) bool { return site.launches() > 1 })
		last := cluster.Status.Redundancy.Coordination.LastRemoteRepairAt.Time
		// pass() advanced the clock once after the launching pass.
		Expect(site.now.Add(-30 * time.Second).Sub(last)).To(BeNumerically(">=", redundancyRemoteHoldDown))
		site.runUntil(200, site.reasonIs(garagev1beta1.ReasonRedundancyVerifiedLocal))
		Expect(site.g.blocksLaunches[remote.id]).To(Equal(1))
	})

	It("A4: defers an unreachable node, reports Partial, and retries it later", func() {
		site := newRedundancyEnvSite("redundancy-a4", 3, func(cluster *garagev1beta2.GarageCluster) {
			cluster.Annotations = map[string]string{garagev1beta1.AnnotationVerifyRedundancy: "go"}
		})
		down := site.g.nodes[2]
		site.g.mu.Lock()
		down.up = false
		site.g.mu.Unlock()
		cluster := site.runUntil(80, site.reasonIs(garagev1beta1.ReasonRedundancyPartial))
		Expect(site.condition(cluster).Status).To(Equal(metav1.ConditionFalse))
		Expect(cluster.Status.Redundancy.Verification.Phase).To(Equal(garagev1beta2.RedundancyPhasePartial))
		Expect(cluster.Status.Redundancy.DeferredNodes).To(HaveLen(1))
		deferred := cluster.Status.Redundancy.DeferredNodes[0]
		Expect(deferred.NodeID).To(Equal(down.id))
		Expect(deferred.Reason).To(Equal(garagev1beta2.RedundancyDeferDown))
		Expect(deferred.RetryAfter).NotTo(BeNil())

		site.g.mu.Lock()
		down.up = true
		site.g.mu.Unlock()
		cluster = site.runUntil(120, site.reasonIs(garagev1beta1.ReasonRedundancyVerified))
		Expect(cluster.Status.Redundancy.DeferredNodes).To(BeEmpty())
		Expect(site.g.blocksLaunches[down.id]).To(Equal(1))
	})

	It("A5: the docs name tranquility as the only repair throttle", func() {
		for _, doc := range []string{"docs/operations/maintenance-and-recovery.md", "docs/reference/operations.md"} {
			raw, err := os.ReadFile(filepath.Join("..", "..", doc))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(raw)).To(ContainSubstring("resyncTranquility"), doc)
			Expect(strings.Contains(string(raw), "verify-redundancy")).To(BeTrue(), doc)
		}
	})
})
