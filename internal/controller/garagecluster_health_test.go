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
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

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
			RemoteClusters: []garagev1beta2.RemoteClusterConfig{{Name: "ottawa"}},
			Network:        garagev1beta2.NetworkConfig{RPCPublicAddr: "node:3901"},
		},
		Status: garagev1beta2.GarageClusterStatus{
			RemoteClusters: []garagev1beta2.RemoteClusterStatus{
				{Name: "ottawa", Connected: false, LastSeen: &recent},
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
			RemoteClusters: []garagev1beta2.RemoteClusterConfig{{Name: "remote-a"}},
		},
		Status: garagev1beta2.GarageClusterStatus{
			RemoteClusters: []garagev1beta2.RemoteClusterStatus{{Name: "remote-a", Connected: true}},
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
	nodes := []garage.NodeInfo{
		{ID: "aaaaaaaaaaaaaaaaaaaa", IsUp: true},                             // up → ignored
		{ID: "bbbbbbbbbbbbbbbbbbbb", IsUp: false, LastSeenSecsAgo: up(120)},  // 2m down → transient
		{ID: "cccccccccccccccccccc", IsUp: false, LastSeenSecsAgo: up(1800)}, // 30m down → flagged
		// never seen but holds a layout role → expected member, flagged
		{ID: "dddddddddddddddddddd", IsUp: false, LastSeenSecsAgo: nil, Role: &garage.NodeAssignedRole{Zone: "z"}},
		// never seen and roleless → bootstrap discovery noise, skipped
		{ID: "eeeeeeeeeeeeeeeeeeee", IsUp: false, LastSeenSecsAgo: nil},
	}
	got := computeUnreachablePeers(nodes)
	if len(got) != 2 {
		t.Fatalf("expected 2 unreachable peers, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "cccccccccccccccc") || !strings.Contains(got[0], "down") {
		t.Fatalf("unexpected first entry: %q", got[0])
	}
	if !strings.Contains(got[1], "never seen") {
		t.Fatalf("expected a never-seen entry, got %q", got[1])
	}
	if strings.Contains(strings.Join(got, "|"), "eeeeeeee") {
		t.Fatal("roleless never-seen peer must be skipped")
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
