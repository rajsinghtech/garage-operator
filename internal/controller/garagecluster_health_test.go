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
	"fmt"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const testHealthRemoteName = "remote-a"

func condStatus(cluster *garagev1beta2.GarageCluster, condType string) (metav1.ConditionStatus, bool) {
	c := meta.FindStatusCondition(cluster.Status.Conditions, condType)
	if c == nil {
		return "", false
	}
	return c.Status, true
}

func TestSetClusterHealthConditions_QuorumAtRisk(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		Status: garagev1beta2.GarageClusterStatus{
			Health: &garagev1beta2.ClusterHealth{
				Partitions: 256, PartitionsQuorum: 200, StorageNodes: 3, StorageNodesOK: 1,
			},
		},
	}
	setClusterHealthConditions(cluster)

	st, ok := condStatus(cluster, garagev1beta1.ConditionQuorumAtRisk)
	if !ok || st != metav1.ConditionTrue {
		t.Fatalf("expected QuorumAtRisk=True, got %v (present=%v)", st, ok)
	}
	if cluster.Status.LayoutDiagnosis == "" {
		t.Fatal("expected a LayoutDiagnosis when quorum is at risk")
	}
}

func TestSetClusterHealthConditions_AllQuorate(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		Status: garagev1beta2.GarageClusterStatus{
			Health: &garagev1beta2.ClusterHealth{
				Partitions: 256, PartitionsQuorum: 256, StorageNodes: 3, StorageNodesOK: 3,
			},
		},
	}
	setClusterHealthConditions(cluster)

	st, _ := condStatus(cluster, garagev1beta1.ConditionQuorumAtRisk)
	if st != metav1.ConditionFalse {
		t.Fatalf("expected QuorumAtRisk=False when all partitions quorate, got %v", st)
	}
	if cluster.Status.LayoutDiagnosis != "" {
		t.Fatalf("expected empty diagnosis for a healthy cluster, got %q", cluster.Status.LayoutDiagnosis)
	}
}

func TestSetClusterHealthConditions_RemoteStale(t *testing.T) {
	old := metav1.NewTime(time.Now().Add(-3 * time.Hour))
	cluster := &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			RemoteClusters: []garagev1beta2.RemoteClusterConfig{{Name: "stpetersburg"}},
			Network:        garagev1beta2.NetworkConfig{RPCPublicAddr: "node.example.com:3901"},
		},
		Status: garagev1beta2.GarageClusterStatus{
			RemoteClusters: []garagev1beta2.RemoteClusterStatus{
				{Name: "stpetersburg", Connected: false, LastSeen: &old},
			},
		},
	}
	setClusterHealthConditions(cluster)

	st, ok := condStatus(cluster, garagev1beta1.ConditionRemoteClustersHealthy)
	if !ok || st != metav1.ConditionFalse {
		t.Fatalf("expected RemoteClustersHealthy=False for a 3h-stale remote, got %v (present=%v)", st, ok)
	}
	// rpc_public_addr is set, so FederationConfigured must be True.
	if st, _ := condStatus(cluster, garagev1beta1.ConditionFederationConfigured); st != metav1.ConditionTrue {
		t.Fatalf("expected FederationConfigured=True, got %v", st)
	}
}

func TestSetClusterHealthConditions_RemoteRecentBlipNotStale(t *testing.T) {
	recent := metav1.NewTime(time.Now().Add(-2 * time.Minute))
	cluster := &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			RemoteClusters: []garagev1beta2.RemoteClusterConfig{{Name: testOttawaName}},
			Network:        garagev1beta2.NetworkConfig{RPCPublicAddr: "node:3901"},
		},
		Status: garagev1beta2.GarageClusterStatus{
			RemoteClusters: []garagev1beta2.RemoteClusterStatus{
				{Name: testOttawaName, Connected: false, LastSeen: &recent},
			},
		},
	}
	setClusterHealthConditions(cluster)
	if st, _ := condStatus(cluster, garagev1beta1.ConditionRemoteClustersHealthy); st != metav1.ConditionTrue {
		t.Fatalf("a 2-minute blip should NOT flip RemoteClustersHealthy False, got %v", st)
	}
}

func TestSetClusterHealthConditions_FederationMissingRPCAddr(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			RemoteClusters: []garagev1beta2.RemoteClusterConfig{{Name: testHealthRemoteName}},
		},
		Status: garagev1beta2.GarageClusterStatus{
			RemoteClusters: []garagev1beta2.RemoteClusterStatus{{Name: testHealthRemoteName, Connected: true}},
		},
	}
	setClusterHealthConditions(cluster)

	st, ok := condStatus(cluster, garagev1beta1.ConditionFederationConfigured)
	if !ok || st != metav1.ConditionFalse {
		t.Fatalf("expected FederationConfigured=False without rpc_public_addr, got %v (present=%v)", st, ok)
	}
	if cluster.Status.LayoutDiagnosis == "" {
		t.Fatal("expected a diagnosis for missing rpc_public_addr under federation")
	}
}

func TestSetClusterHealthConditions_NodeLocalPoolsRequirePerIdentityRoutes(t *testing.T) {
	capacity := resource.MustParse("500Gi")
	cluster := &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			RemoteClusters: []garagev1beta2.RemoteClusterConfig{{Name: testHealthRemoteName}},
			Network:        garagev1beta2.NetworkConfig{RPCPublicAddr: testSharedRPCPublicAddr},
			Storage: &garagev1beta2.StorageSpec{NodeLocalPools: []garagev1beta2.NodeLocalPoolSpec{{
				Name:     testTagLocal,
				Capacity: &capacity,
			}}},
		},
	}
	setClusterHealthConditions(cluster)
	if st, _ := condStatus(cluster, garagev1beta1.ConditionFederationConfigured); st != metav1.ConditionFalse {
		t.Fatalf("shared RPC address must not mask an unaddressed node-local pool, got %v", st)
	}

	cluster.Spec.Storage.NodeLocalPools[0].Network = &garagev1beta2.NodeLocalPoolNetworkSpec{
		RPCPublicAddrTemplate: testNodeAddressTemplate,
	}
	setClusterHealthConditions(cluster)
	if st, _ := condStatus(cluster, garagev1beta1.ConditionFederationConfigured); st != metav1.ConditionTrue {
		t.Fatalf("per-node-local pool address should satisfy federation routing, got %v", st)
	}
}

func TestClusterRPCAddressGaps_MixedStorageGroups(t *testing.T) {
	capacity := resource.MustParse("500Gi")
	cluster := &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			LayoutPolicy: LayoutPolicyAuto,
			Storage: &garagev1beta2.StorageSpec{
				Replicas:       1,
				NodeLocalPools: []garagev1beta2.NodeLocalPoolSpec{{Name: testTagLocal, Capacity: &capacity}},
			},
			Gateway: &garagev1beta2.GatewaySpec{Replicas: 1},
		},
	}

	gaps := strings.Join(clusterRPCAddressGaps(cluster), ",")
	for _, want := range []string{"default StatefulSet/PVC group", "gateway tier", "node-local pool local"} {
		if !strings.Contains(gaps, want) {
			t.Fatalf("gaps %q do not include %q", gaps, want)
		}
	}

	cluster.Spec.Storage.RPCPublicAddr = "storage-{ordinal}.example.net:3901"
	cluster.Spec.Gateway.RPCPublicAddr = "gateway-{ordinal}.example.net:3901"
	gaps = strings.Join(clusterRPCAddressGaps(cluster), ",")
	if gaps != "node-local pool local" {
		t.Fatalf("tier addresses must not mask an unaddressed node-local pool, got %q", gaps)
	}

	cluster.Spec.Storage.NodeLocalPools[0].Network = &garagev1beta2.NodeLocalPoolNetworkSpec{
		RPCPublicAddrTemplate: testNodeAddressTemplate,
	}
	if gaps := clusterRPCAddressGaps(cluster); len(gaps) != 0 {
		t.Fatalf("all identity groups are addressed, got gaps %v", gaps)
	}

	cluster.Spec.Storage.RPCPublicAddr = ""
	cluster.Spec.Gateway.RPCPublicAddr = ""
	cluster.Spec.Network.RPCPublicAddrSubnet = "100.64.0.0/10"
	if gaps := clusterRPCAddressGaps(cluster); len(gaps) != 0 {
		t.Fatalf("an explicit routable subnet should cover every identity, got gaps %v", gaps)
	}
}

func TestClusterRPCAddressGaps_MixedManualSMBAndNodeLocalPool(t *testing.T) {
	capacity := resource.MustParse("500Gi")
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: testOttawaName, Namespace: testGarageValue},
		Spec: garagev1beta2.GarageClusterSpec{
			LayoutPolicy: LayoutPolicyManual,
			Storage: &garagev1beta2.StorageSpec{
				Replicas: 0,
				NodeLocalPools: []garagev1beta2.NodeLocalPoolSpec{{
					Name: testTagLocal, Capacity: &capacity,
					Network: &garagev1beta2.NodeLocalPoolNetworkSpec{RPCPublicAddrTemplate: testNodeAddressTemplate},
				}},
			},
		},
	}
	smb := garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: testSMBNodeName, Namespace: testGarageValue},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name},
		},
	}
	if gaps := clusterRPCAddressGaps(cluster, []garagev1beta1.GarageNode{smb}); len(gaps) != 1 || gaps[0] != "storage GarageNode smb-a" {
		t.Fatalf("unaddressed Manual SMB identity was not diagnosed: %v", gaps)
	}
	smb.Spec.Network = &garagev1beta1.NodeNetworkConfig{RPCPublicAddr: "smb-a.example.net:3901"}
	if gaps := clusterRPCAddressGaps(cluster, []garagev1beta1.GarageNode{smb}); len(gaps) != 0 {
		t.Fatalf("addressed SMB and node-local-pool identities should be complete, got %v", gaps)
	}
}

func TestSetClusterHealthConditions_NoFederationClearsConditions(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		Status: garagev1beta2.GarageClusterStatus{
			Conditions: []metav1.Condition{
				{Type: garagev1beta1.ConditionRemoteClustersHealthy, Status: metav1.ConditionFalse, Reason: "x", LastTransitionTime: metav1.Now()},
				{Type: garagev1beta1.ConditionFederationConfigured, Status: metav1.ConditionFalse, Reason: "x", LastTransitionTime: metav1.Now()},
			},
		},
	}
	setClusterHealthConditions(cluster)

	if _, ok := condStatus(cluster, garagev1beta1.ConditionRemoteClustersHealthy); ok {
		t.Fatal("RemoteClustersHealthy must be removed for a non-federated cluster")
	}
	if _, ok := condStatus(cluster, garagev1beta1.ConditionFederationConfigured); ok {
		t.Fatal("FederationConfigured must be removed for a non-federated cluster")
	}
}

func TestComputeUnreachablePeers(t *testing.T) {
	up := func(secs uint64) *uint64 { return &secs }
	cap1 := uint64(1 << 30)
	storageRole := &garage.NodeAssignedRole{Zone: "z", Capacity: &cap1} // storage (capacity != nil)
	gatewayRole := &garage.NodeAssignedRole{Zone: "z"}                  // gateway (capacity == nil)
	nodes := []garage.NodeInfo{
		{ID: "aaaaaaaaaaaaaaaaaaaa", IsUp: true},                                                // up → ignored
		{ID: "bbbbbbbbbbbbbbbbbbbb", IsUp: false, LastSeenSecsAgo: up(120), Role: storageRole},  // 2m down → transient
		{ID: "cccccccccccccccccccc", IsUp: false, LastSeenSecsAgo: up(1800), Role: storageRole}, // 30m down, storage → flagged
		// never seen but holds a storage layout role → expected member, flagged
		{ID: "dddddddddddddddddddd", IsUp: false, LastSeenSecsAgo: nil, Role: storageRole},
		// never seen and roleless → bootstrap discovery noise, skipped
		{ID: "eeeeeeeeeeeeeeeeeeee", IsUp: false, LastSeenSecsAgo: nil},
		// SUSTAINED down but roleless → a discarded identity Garage still remembers;
		// not actionable, must be skipped (#224-class noise).
		{ID: "ffffffffffffffffffff", IsUp: false, LastSeenSecsAgo: up(70000)},
		// SUSTAINED down + DRAINING → a storage node mid-removal (role==nil + draining
		// in a prior layout version); a STUCK drain is exactly when the warning matters,
		// so it must still be flagged despite role==nil.
		{ID: "gggggggggggggggggggg", IsUp: false, LastSeenSecsAgo: up(1800), Draining: true},
		// SUSTAINED down gateway peer (capacity==nil) → reaped by reconcileGatewayTombstones,
		// not ConnectClusterNodes; must be skipped to avoid misleading noise (#237).
		{ID: "hhhhhhhhhhhhhhhhhhhh", IsUp: false, LastSeenSecsAgo: up(1800), Role: gatewayRole},
	}
	got := computeUnreachablePeers(nodes)
	if len(got) != 3 {
		t.Fatalf("expected 3 unreachable peers, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "cccccccccccccccc") || !strings.Contains(got[0], "down") {
		t.Fatalf("unexpected first entry: %q", got[0])
	}
	if !strings.Contains(got[1], "never seen") {
		t.Fatalf("expected a never-seen entry, got %q", got[1])
	}
	joined := strings.Join(got, "|")
	if strings.Contains(joined, "eeeeeeee") {
		t.Fatal("roleless never-seen peer must be skipped")
	}
	if strings.Contains(joined, "ffffffff") {
		t.Fatal("roleless sustained-down peer (discarded identity) must be skipped")
	}
	if !strings.Contains(joined, "gggggggggggggggg") {
		t.Fatal("sustained-down draining node must still be flagged (stuck-drain visibility)")
	}
	if strings.Contains(joined, "hhhhhhhhhhhhhhhh") {
		t.Fatal("sustained-down gateway peer (capacity=nil) must be skipped — tombstone reaper handles them")
	}
}

func TestSetClusterHealthConditions_PeerUnreachable(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		Status: garagev1beta2.GarageClusterStatus{
			Health:           &garagev1beta2.ClusterHealth{Partitions: 256, PartitionsQuorum: 256},
			UnreachablePeers: []string{"abc123 (down 30m0s)"},
		},
	}
	setClusterHealthConditions(cluster)
	st, ok := condStatus(cluster, garagev1beta1.ConditionPeerUnreachable)
	if !ok || st != metav1.ConditionTrue {
		t.Fatalf("expected PeerUnreachable=True, got %v (present=%v)", st, ok)
	}
	if cluster.Status.LayoutDiagnosis == "" {
		t.Fatal("expected a diagnosis when a peer is sustained-unreachable")
	}

	// Clears when peers recover.
	cluster.Status.UnreachablePeers = nil
	setClusterHealthConditions(cluster)
	if st, _ := condStatus(cluster, garagev1beta1.ConditionPeerUnreachable); st != metav1.ConditionFalse {
		t.Fatalf("expected PeerUnreachable=False after recovery, got %v", st)
	}
}

func TestSetClusterHealthConditions_GatewayLayoutDegraded(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		Status: garagev1beta2.GarageClusterStatus{
			Health:                  &garagev1beta2.ClusterHealth{Partitions: 256, PartitionsQuorum: 256},
			GatewayNodesNotInLayout: []string{"gc-gateway-0"},
		},
	}
	setClusterHealthConditions(cluster)
	st, ok := condStatus(cluster, garagev1beta1.ConditionGatewayLayoutDegraded)
	if !ok || st != metav1.ConditionTrue {
		t.Fatalf("expected GatewayLayoutDegraded=True, got %v (present=%v)", st, ok)
	}
	if cluster.Status.LayoutDiagnosis == "" {
		t.Fatal("expected a diagnosis when a gateway node is out of layout")
	}
	// Clears when the role returns.
	cluster.Status.GatewayNodesNotInLayout = nil
	setClusterHealthConditions(cluster)
	if st, _ := condStatus(cluster, garagev1beta1.ConditionGatewayLayoutDegraded); st != metav1.ConditionFalse {
		t.Fatalf("expected GatewayLayoutDegraded=False after recovery, got %v", st)
	}
}

func TestSetClusterHealthConditions_QuorumIsMostSevere(t *testing.T) {
	old := metav1.NewTime(time.Now().Add(-5 * time.Hour))
	cluster := &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			RemoteClusters: []garagev1beta2.RemoteClusterConfig{{Name: "r"}},
		},
		Status: garagev1beta2.GarageClusterStatus{
			Health:         &garagev1beta2.ClusterHealth{Partitions: 256, PartitionsQuorum: 100, StorageNodes: 3, StorageNodesOK: 1},
			RemoteClusters: []garagev1beta2.RemoteClusterStatus{{Name: "r", Connected: false, LastSeen: &old}},
		},
	}
	setClusterHealthConditions(cluster)
	// The diagnosis line should be the quorum problem (most severe), not the remote one.
	if got := cluster.Status.LayoutDiagnosis; got == "" || !strings.Contains(got, "write quorum") {
		t.Fatalf("expected the quorum problem to win the diagnosis line, got %q", got)
	}
}

func TestSetClusterHealthConditions_BoundsRepeatedMemberInventories(t *testing.T) {
	t.Parallel()
	old := metav1.NewTime(time.Now().Add(-5 * time.Hour))
	cluster := &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			Network: garagev1beta2.NetworkConfig{RPCPublicAddr: "node.example.com:3901"},
		},
		Status: garagev1beta2.GarageClusterStatus{
			Health: &garagev1beta2.ClusterHealth{Partitions: 256, PartitionsQuorum: 256},
		},
	}
	for i := 0; i < 256; i++ {
		name := fmt.Sprintf("member-%03d-%s", i, strings.Repeat("x", 48))
		cluster.Spec.RemoteClusters = append(cluster.Spec.RemoteClusters,
			garagev1beta2.RemoteClusterConfig{Name: name})
		cluster.Status.RemoteClusters = append(cluster.Status.RemoteClusters,
			garagev1beta2.RemoteClusterStatus{Name: name, LastSeen: &old})
		cluster.Status.UnreachablePeers = append(cluster.Status.UnreachablePeers,
			fmt.Sprintf("%016x (down 2562047h47m)", i))
		cluster.Status.GatewayNodesNotInLayout = append(cluster.Status.GatewayNodesNotInLayout, name)
	}

	setClusterHealthConditions(cluster)
	for _, conditionType := range []string{
		garagev1beta1.ConditionRemoteClustersHealthy,
		garagev1beta1.ConditionPeerUnreachable,
		garagev1beta1.ConditionGatewayLayoutDegraded,
	} {
		condition := meta.FindStatusCondition(cluster.Status.Conditions, conditionType)
		if condition == nil {
			t.Fatalf("condition %s was not published", conditionType)
		}
		if len(condition.Message) > statusConditionMessageLimit {
			t.Fatalf("condition %s duplicated an unbounded inventory (%d bytes)", conditionType, len(condition.Message))
		}
		if !strings.Contains(condition.Message, "256 total") || !strings.Contains(condition.Message, "251 more") {
			t.Fatalf("condition %s does not expose a bounded count/examples summary: %q", conditionType, condition.Message)
		}
	}
	if len(cluster.Status.LayoutDiagnosis) > statusConditionMessageLimit ||
		!strings.Contains(cluster.Status.LayoutDiagnosis, "256 total") {
		t.Fatalf("LayoutDiagnosis is not the bounded severe-condition summary: %q", cluster.Status.LayoutDiagnosis)
	}
}

func TestSetClusterHealthConditions_MissingRemoteStatusNeverConnected(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		Spec: garagev1beta2.GarageClusterSpec{
			RemoteClusters: []garagev1beta2.RemoteClusterConfig{
				{Name: "us-east", Zone: "us-east"},
			},
			Network: garagev1beta2.NetworkConfig{RPCPublicAddr: "node.example.com:3901"},
		},
		Status: garagev1beta2.GarageClusterStatus{},
	}
	setClusterHealthConditions(cluster)

	st, ok := condStatus(cluster, garagev1beta1.ConditionRemoteClustersHealthy)
	if !ok || st != metav1.ConditionFalse {
		t.Fatalf("expected RemoteClustersHealthy=False when status.remoteClusters is empty, got %v (present=%v)", st, ok)
	}
	cond := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionRemoteClustersHealthy)
	if cond == nil || !strings.Contains(cond.Message, "us-east (never connected)") {
		t.Fatalf("expected never connected message for missing remote status, got %v", cond)
	}
}
