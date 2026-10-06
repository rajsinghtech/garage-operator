//go:build garagecontract

package contract

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Garage's staging area is a last-writer-wins map keyed by node ID. The
// controllers' staged-ownership checks (requireExclusiveStagedRoleChanges) and
// the layout fakes rely on re-staging replacing, never duplicating, an entry.
func TestContract_StagedLayoutIsLastWriterWinsPerNode(t *testing.T) {
	nodes := startCluster(t, 1, 1)
	ctx := context.Background()
	c, id := nodes[0].client, nodes[0].id
	for _, capacity := range []uint64{1 << 30, 2 << 30} {
		if err := c.UpdateClusterLayout(ctx, []garage.NodeRoleChange{{ID: id, Zone: "z1", Capacity: ptr(capacity), Tags: []string{"a"}}}); err != nil {
			t.Fatal(err)
		}
	}
	layout, err := c.GetClusterLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(layout.StagedRoleChanges) != 1 {
		t.Fatalf("re-staging one node must keep one staged entry, got %d: %+v", len(layout.StagedRoleChanges), layout.StagedRoleChanges)
	}
	if got := layout.StagedRoleChanges[0].Capacity; got == nil || *got != 2<<30 {
		t.Fatalf("last write must win, got capacity %v", got)
	}
}

// Re-staging an identical removal must stay a single idempotent entry (#467's
// fix re-stages a removal that an interrupted reconcile already staged).
func TestContract_RestagingIdenticalRemovalIsIdempotent(t *testing.T) {
	nodes := startCluster(t, 2, 1)
	ctx := context.Background()
	a, b := nodes[0], nodes[1]
	if _, err := a.client.ConnectNode(ctx, b.id, b.rpcAddr); err != nil {
		t.Fatal(err)
	}
	assignAndApply(t, a, a.id, b.id)
	for i := 0; i < 2; i++ {
		if err := a.client.UpdateClusterLayout(ctx, []garage.NodeRoleChange{{ID: b.id, Remove: true}}); err != nil {
			t.Fatalf("staging removal #%d: %v", i+1, err)
		}
	}
	layout, err := a.client.GetClusterLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(layout.StagedRoleChanges) != 1 || !layout.StagedRoleChanges[0].Remove || layout.StagedRoleChanges[0].ID != b.id {
		t.Fatalf("want exactly one staged removal of %s, got %+v", b.id[:8], layout.StagedRoleChanges)
	}
	if err := a.client.ApplyStagedLayoutChanges(ctx); err != nil {
		t.Fatalf("applying the re-staged removal: %v", err)
	}
	after, err := a.client.GetClusterLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range after.Roles {
		if r.ID == b.id {
			t.Fatal("removed role is still in the committed layout")
		}
	}
}

// Re-staging a node's committed role over a pending removal cancels the
// removal: Garage drops a staged entry identical to the committed role, so the
// staging area ends up empty rather than holding a no-op change (input for
// #468: overriding an operator-owned leftover).
func TestContract_RestagingCommittedRoleCancelsPendingRemoval(t *testing.T) {
	nodes := startCluster(t, 1, 1)
	ctx := context.Background()
	c, id := nodes[0].client, nodes[0].id
	assignAndApply(t, nodes[0], id)
	before, err := c.GetClusterLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.UpdateClusterLayout(ctx, []garage.NodeRoleChange{{ID: id, Remove: true}}); err != nil {
		t.Fatal(err)
	}
	role := before.Roles[0]
	if err := c.UpdateClusterLayout(ctx, []garage.NodeRoleChange{{ID: id, Zone: role.Zone, Capacity: role.Capacity, Tags: role.Tags}}); err != nil {
		t.Fatal(err)
	}
	staged, err := c.GetClusterLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(staged.StagedRoleChanges) != 0 {
		t.Fatalf("re-staging the committed role must cancel the pending removal and leave nothing staged, got %+v", staged.StagedRoleChanges)
	}
	// ApplyStagedLayoutChanges has nothing to commit and must not touch the layout.
	if err := c.ApplyStagedLayoutChanges(ctx); err != nil {
		t.Fatalf("ApplyStagedLayoutChanges after the cancel: %v", err)
	}
	after, err := c.GetClusterLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Version != staged.Version || len(after.Roles) != 1 || after.Roles[0].ID != id {
		t.Fatalf("committed layout must be untouched: version %d -> %d, roles %+v", staged.Version, after.Version, after.Roles)
	}
}

// The client sends "tags" without omitempty because Garage's untagged role
// enum needs it: a null tags field is rejected as a 400, an empty list is
// accepted. Every staging path in the operator must therefore pass a non-nil
// slice; this pins why.
func TestContract_NullTagsAreRejected(t *testing.T) {
	nodes := startCluster(t, 1, 1)
	ctx := context.Background()
	c, id := nodes[0].client, nodes[0].id
	err := c.UpdateClusterLayout(ctx, []garage.NodeRoleChange{{ID: id, Zone: "z1", Capacity: ptr(uint64(1 << 30))}})
	wantStatus(t, "staging a role with null tags", err, 400)
	if !garage.IsBadRequest(err) {
		t.Fatalf("null tags rejection must classify as BadRequest: %v", err)
	}
	if err := c.UpdateClusterLayout(ctx, []garage.NodeRoleChange{{ID: id, Zone: "z1", Capacity: ptr(uint64(1 << 30)), Tags: []string{}}}); err != nil {
		t.Fatalf("staging a role with an empty tag list: %v", err)
	}
	// A removal needs no tags.
	if err := c.UpdateClusterLayout(ctx, []garage.NodeRoleChange{{ID: id, Remove: true}}); err != nil {
		t.Fatalf("staging a removal with null tags: %v", err)
	}
}

// RevertClusterLayout clears staged roles and staged parameters.
func TestContract_RevertClearsStagedRolesAndParameters(t *testing.T) {
	nodes := startCluster(t, 1, 1)
	ctx := context.Background()
	c, id := nodes[0].client, nodes[0].id
	assignAndApply(t, nodes[0], id)
	if err := c.UpdateClusterLayoutWithParams(ctx, garage.UpdateClusterLayoutRequest{
		Roles:      []garage.NodeRoleChange{storageRole(id, "z2", 3<<30)},
		Parameters: &garage.LayoutParameters{ZoneRedundancy: &garage.ZoneRedundancy{AtLeast: ptr(1)}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.RevertClusterLayout(ctx); err != nil {
		t.Fatalf("revert: %v", err)
	}
	layout, err := c.GetClusterLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(layout.StagedRoleChanges) != 0 || layout.StagedParameters != nil {
		t.Fatalf("revert must clear staging, got roles=%+v params=%+v", layout.StagedRoleChanges, layout.StagedParameters)
	}
}

// Garage's raw ApplyClusterLayout commits a new version even with nothing
// staged, which is why ApplyStagedLayoutChanges guards the empty case
// client-side. A raw Apply of the wrong version must fail with a status the
// operator surfaces as a plain error (not 404/409/replication constraint).
func TestContract_ApplyEmptyAndVersionMismatch(t *testing.T) {
	nodes := startCluster(t, 1, 1)
	ctx := context.Background()
	c, id := nodes[0].client, nodes[0].id
	assignAndApply(t, nodes[0], id)
	before, err := c.GetClusterLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ApplyStagedLayoutChanges(ctx); err != nil {
		t.Fatalf("ApplyStagedLayoutChanges with nothing staged: %v", err)
	}
	mid, err := c.GetClusterLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if mid.Version != before.Version {
		t.Fatalf("empty ApplyStagedLayoutChanges bumped version %d -> %d", before.Version, mid.Version)
	}
	if err := c.ApplyClusterLayout(ctx, mid.Version+1); err != nil {
		t.Fatalf("raw Apply with nothing staged: %v", err)
	}
	raw, err := c.GetClusterLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if raw.Version != mid.Version+1 {
		t.Fatalf("raw empty Apply is expected to commit a new version (the client guard exists because of it): %d -> %d", mid.Version, raw.Version)
	}

	if err := c.UpdateClusterLayout(ctx, []garage.NodeRoleChange{storageRole(id, "z1", 5<<30)}); err != nil {
		t.Fatal(err)
	}
	err = c.ApplyClusterLayout(ctx, raw.Version+5)
	if err == nil {
		t.Fatal("Apply with a wrong version must fail")
	}
	if garage.IsNotFound(err) || garage.IsConflict(err) || garage.IsReplicationConstraint(err) {
		t.Fatalf("version mismatch must not look like NotFound/Conflict/replication constraint: %v", err)
	}
	// Garage reports a stale version as a 500 InternalError, which the operator
	// treats as a plain retryable failure (another writer applied first).
	wantStatus(t, "version-mismatch Apply", err, 500)
	wantMessage(t, "version-mismatch Apply", err, "layout version")
	after, lerr := c.GetClusterLayout(ctx)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if after.Version != raw.Version || len(after.StagedRoleChanges) != 1 {
		t.Fatalf("a rejected Apply must keep the version and the staged change: version %d -> %d, staged %+v", raw.Version, after.Version, after.StagedRoleChanges)
	}
}

// The operator classifies insufficient-capacity Apply rejections with
// IsReplicationConstraint (message matching). Pin it per Garage version.
func TestContract_ReplicationConstraintIsDetected(t *testing.T) {
	nodes := startCluster(t, 1, 2)
	ctx := context.Background()
	c, id := nodes[0].client, nodes[0].id
	if err := c.UpdateClusterLayout(ctx, []garage.NodeRoleChange{storageRole(id, "z1", 1<<30)}); err != nil {
		t.Fatal(err)
	}
	err := c.ApplyStagedLayoutChanges(ctx)
	if err == nil {
		t.Fatal("one storage node with replication_factor=2 must be rejected")
	}
	if !garage.IsReplicationConstraint(err) {
		t.Fatalf("IsReplicationConstraint no longer matches Garage's rejection (status %d): %v", apiStatus(err), err)
	}
	// The rejected Apply leaves the change staged (federated bootstrap relies on it).
	layout, lerr := c.GetClusterLayout(ctx)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if len(layout.StagedRoleChanges) != 1 {
		t.Fatalf("rejected Apply must leave the staged change, got %+v", layout.StagedRoleChanges)
	}
}

// Removing the last storage node of a committed layout is rejected and also
// classified as a replication constraint (finalizers map it to retryable).
func TestContract_RemovingLastStorageNodeIsReplicationConstraint(t *testing.T) {
	nodes := startCluster(t, 1, 1)
	ctx := context.Background()
	c, id := nodes[0].client, nodes[0].id
	assignAndApply(t, nodes[0], id)
	if err := c.UpdateClusterLayout(ctx, []garage.NodeRoleChange{{ID: id, Remove: true}}); err != nil {
		t.Fatal(err)
	}
	err := c.ApplyStagedLayoutChanges(ctx)
	if err == nil {
		t.Fatal("removing the only storage node must be rejected")
	}
	if !garage.IsReplicationConstraint(err) {
		t.Fatalf("IsReplicationConstraint does not match last-node removal (status %d): %v", apiStatus(err), err)
	}
}

// ConnectClusterNodes is called on every reconcile. A failed connection is a
// per-entry failure inside a 200 response, which the client must turn into an
// error; repeating a successful connect must keep succeeding. Once a peer is
// connected, Garage reports success for it regardless of the address given.
func TestContract_ConnectNodeRepeatedAndUnreachable(t *testing.T) {
	nodes := startCluster(t, 2, 1)
	ctx := context.Background()
	a, b := nodes[0], nodes[1]
	if _, err := a.client.ConnectNode(ctx, b.id, "127.0.0.1:1"); err == nil {
		t.Fatal("connecting to an unreachable address must return an error")
	} else if apiStatus(err) != -1 {
		t.Fatalf("a failed connect is a per-entry failure, not an HTTP error status: %v", err)
	}
	if _, err := a.client.ConnectNode(ctx, randomHex(t, 32), b.rpcAddr); err == nil {
		t.Fatal("connecting with a wrong node ID must return an error")
	}
	if _, err := a.client.ConnectNode(ctx, "not-a-node-id", b.rpcAddr); err == nil {
		t.Fatal("connecting with an unparsable node ID must return an error")
	}
	for i := 0; i < 3; i++ {
		res, err := a.client.ConnectNode(ctx, b.id, b.rpcAddr)
		if err != nil || res == nil || !res.Success {
			t.Fatalf("ConnectNode #%d: %+v %v", i+1, res, err)
		}
	}
	eventually(t, 15*time.Second, "peer reported up", func() (bool, string) {
		status, err := a.client.GetClusterStatus(ctx)
		if err != nil {
			return false, err.Error()
		}
		for _, n := range status.Nodes {
			if n.ID == b.id && n.IsUp {
				return true, ""
			}
		}
		return false, fmt.Sprintf("%+v", status.Nodes)
	})
	if _, err := a.client.ConnectNode(ctx, b.id, "127.0.0.1:1"); err != nil {
		t.Fatalf("an already-connected peer is expected to report success for any address: %v", err)
	}
}

// Health, status, self-identity and layout history decode into the fields the
// health and drain logic reads.
func TestContract_HealthStatusAndHistoryFields(t *testing.T) {
	nodes := startCluster(t, 1, 1)
	ctx := context.Background()
	c, id := nodes[0].client, nodes[0].id
	assignAndApply(t, nodes[0], id)
	waitLayoutReady(t, nodes[0])
	h, err := c.GetClusterHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h.Status != "healthy" || h.StorageNodes != 1 || h.StorageNodesUp != 1 || h.Partitions != 256 || h.PartitionsAllOK != 256 || h.ConnectedNodes != 1 {
		t.Fatalf("unexpected health decode: %+v", h)
	}
	st, err := c.GetClusterStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.LayoutVersion < 1 || len(st.Nodes) != 1 || st.Nodes[0].ID != id || st.Nodes[0].Role == nil || st.Nodes[0].Role.Capacity == nil {
		t.Fatalf("unexpected status decode: %+v", st)
	}
	self, err := c.GetSelfNodeInfo(ctx)
	if err != nil || self.NodeID != id {
		t.Fatalf("self node info: %+v %v", self, err)
	}
	hist, err := c.GetClusterLayoutHistory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if hist.CurrentVersion != st.LayoutVersion || len(hist.Versions) == 0 {
		t.Fatalf("unexpected history decode: %+v", hist)
	}
	if !hist.DataMigrationSettled() {
		t.Logf("history not settled yet on a single fresh node: %+v", hist)
	}
}
