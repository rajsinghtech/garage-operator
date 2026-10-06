//go:build garagecontract

package contract

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Per-node status fields read by the node controller (version gating, disk
// usage) and the drain/health logic.
func TestContract_NodeStatusFields(t *testing.T) {
	nd := readyNode(t)
	st, err := nd.client.GetClusterStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n := st.Nodes[0]
	// Releases report "vX.Y.Z"; main-v2 builds report the commit SHA. The
	// operator only displays it (status.version, status.buildInfo).
	if n.GarageVersion == nil || strings.TrimSpace(*n.GarageVersion) == "" {
		t.Fatal("garageVersion missing")
	}
	if want := os.Getenv("GARAGE_EXPECT_VERSION"); want != "" && *n.GarageVersion != want {
		t.Fatalf("garageVersion = %q, want %q", *n.GarageVersion, want)
	}
	if n.Address == nil || *n.Address != nd.rpcAddr {
		t.Fatalf("addr = %v, want %s", n.Address, nd.rpcAddr)
	}
	if n.Hostname == nil || *n.Hostname == "" {
		t.Fatal("hostname missing")
	}
	if n.DataPartition == nil || n.DataPartition.Total == 0 || n.MetadataPartition == nil || n.MetadataPartition.Total == 0 {
		t.Fatalf("data/metadata partition stats missing: %+v %+v", n.DataPartition, n.MetadataPartition)
	}
	if !n.IsUp || n.Draining || n.LastSeenSecsAgo != nil {
		t.Fatalf("a live self node must be up, not draining, with no lastSeenSecsAgo: %+v", n)
	}
}

// A stopped peer is reported isUp=false with lastSeenSecsAgo set (the gateway
// sustained-down and health "down for" logic key off both), and cluster health stops being healthy
// with storageNodesUp counting only live storage nodes.
func TestContract_DownPeerStatusAndHealth(t *testing.T) {
	nodes := startCluster(t, 2, 1)
	ctx := context.Background()
	a, b := nodes[0], nodes[1]
	if _, err := a.client.ConnectNode(ctx, b.id, b.rpcAddr); err != nil {
		t.Fatal(err)
	}
	assignAndApply(t, a, a.id, b.id)
	waitLayoutReady(t, a)
	// lastSeenSecsAgo is only set once a ping has completed; a peer that dies
	// before its first ping stays "never seen" (nil), which the health logic
	// reports as such. Wait for the first ping so the down state is measurable.
	eventually(t, 60*time.Second, "peer pinged at least once", func() (bool, string) {
		st, err := a.client.GetClusterStatus(ctx)
		if err != nil {
			return false, err.Error()
		}
		for _, n := range st.Nodes {
			if n.ID == b.id {
				return n.IsUp && n.LastSeenSecsAgo != nil, fmt.Sprintf("%+v", n)
			}
		}
		return false, "peer missing from status"
	})
	b.stop(t)

	eventually(t, 45*time.Second, "peer reported down with lastSeenSecsAgo", func() (bool, string) {
		st, err := a.client.GetClusterStatus(ctx)
		if err != nil {
			return false, err.Error()
		}
		for _, n := range st.Nodes {
			if n.ID == b.id {
				// A down peer keeps its role and lastSeenSecsAgo but loses addr,
				// hostname and version: reconnect paths must not rely on the
				// status address of a down node.
				return !n.IsUp && n.LastSeenSecsAgo != nil && n.Role != nil && n.Address == nil, fmt.Sprintf("%+v", n)
			}
		}
		return false, "peer missing from status"
	})
	h, err := a.client.GetClusterHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h.Status == "healthy" || h.StorageNodes != 2 || h.StorageNodesUp != 1 || h.ConnectedNodes != 1 || h.KnownNodes != 2 {
		t.Fatalf("health with one of two storage nodes down: %+v", h)
	}
	if h.PartitionsAllOK >= h.Partitions {
		t.Fatalf("partitionsAllOk must drop when a replica holder is down: %+v", h)
	}
	t.Logf("health with a down peer: %+v", h)
}
