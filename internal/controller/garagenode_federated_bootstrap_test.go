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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Two federated sites, each a GarageCluster named "garage" in the same
// namespace (the multi-cluster e2e shape), one storage node per site and
// replication factor 2. Only the immutable cluster-uid tag tells them apart.
const (
	fbNamespace = "garage-operator-system"
	fbLocalUID  = "uid-site-b"
	fbRemoteUID = "uid-site-a"
	fbLocalZone = "zone-b"
	fbRemZone   = "zone-a"
)

var (
	fbLocalID  = strings.Repeat("6e", 32)
	fbRemoteID = strings.Repeat("80", 32)
)

func fbCluster() *garagev1beta2.GarageCluster {
	return &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "garage", Namespace: fbNamespace, UID: types.UID(fbLocalUID)},
		Spec: garagev1beta2.GarageClusterSpec{
			RemoteClusters: []garagev1beta2.RemoteClusterConfig{{Name: "cluster1", Zone: fbRemZone}},
		},
	}
}

func fbRole(id, zone, uid string) garage.NodeRoleChange {
	capacity := uint64(10 << 30)
	return garage.NodeRoleChange{
		ID:       id,
		Zone:     zone,
		Capacity: &capacity,
		Tags: desiredNodeRoleTags(nil, "",
			"cluster:garage/"+fbNamespace, nodeClusterUIDTagPrefix+uid, "tier:"+tierStorage),
	}
}

func fbReconciler(t *testing.T, cluster *garagev1beta2.GarageCluster) *GarageNodeReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := garagev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := garagev1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	local := &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "garage-storage-0", Namespace: fbNamespace},
		Spec:       garagev1beta1.GarageNodeSpec{ClusterRef: garagev1beta1.ClusterReference{Name: cluster.Name}},
		Status:     garagev1beta1.GarageNodeStatus{NodeID: fbLocalID},
	}
	kube := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, local).Build()
	return &GarageNodeReconciler{Client: kube, APIReader: kube}
}

// fbPeers serves GetClusterStatus reporting the given node IDs as up.
func fbPeers(t *testing.T, up ...string) *garage.Client {
	t.Helper()
	srv := httptest.NewServer(&fbGarage{up: up, roles: map[string]garage.NodeRoleChange{}, staged: map[string]garage.NodeRoleChange{}})
	t.Cleanup(srv.Close)
	return garage.NewClient(srv.URL, "token")
}

// TestGarageNodeStagingIntent_AdmitsRemoteSiteBootstrapRole reproduces the
// multi-cluster e2e single-replica deadlock (main, run 37514491138): the remote
// site's GarageNode staged its own role (its Apply failed the replication
// factor), Garage gossiped that staging here before this GarageNode staged its
// role, and the GarageNode then refused forever with "staged node ... is not an
// assignable live GarageNode owned by this cluster".
func TestGarageNodeStagingIntent_AdmitsRemoteSiteBootstrapRole(t *testing.T) {
	cluster := fbCluster()
	r := fbReconciler(t, cluster)
	desired := fbRole(fbLocalID, fbLocalZone, fbLocalUID)
	remote := fbRole(fbRemoteID, fbRemZone, fbRemoteUID)
	layout := &garage.ClusterLayout{StagedRoleChanges: []garage.NodeRoleChange{remote}}

	intended, err := r.garageNodeStagingIntent(context.Background(), cluster, layout, desired, fbPeers(t, fbLocalID, fbRemoteID))
	if err != nil {
		t.Fatalf("staging intent refused the remote site's bootstrap role: %v", err)
	}
	if len(intended) != 2 || !sameStagedRoleChange(intended[0], desired) || !sameStagedRoleChange(intended[1], remote) {
		t.Fatalf("intended = %+v, want [local desired, remote staged]", intended)
	}
}

func TestGarageNodeStagingIntent_StillRefusesForeignStagedChanges(t *testing.T) {
	cluster := fbCluster()
	r := fbReconciler(t, cluster)
	desired := fbRole(fbLocalID, fbLocalZone, fbLocalUID)

	untagged := fbRole(fbRemoteID, fbRemZone, fbRemoteUID)
	untagged.Tags = []string{"cluster:garage/" + fbNamespace, "tier:" + tierStorage}

	noTier := fbRole(fbRemoteID, fbRemZone, fbRemoteUID)
	noTier.Tags = []string{nodeClusterUIDTagPrefix + fbRemoteUID}

	cases := map[string]garage.NodeRoleChange{
		"removal":                           {ID: fbRemoteID, Remove: true},
		"zone is not a remoteClusters zone": fbRole(fbRemoteID, "zone-x", fbRemoteUID),
		"local zone":                        fbRole(fbRemoteID, fbLocalZone, fbRemoteUID),
		"own cluster uid but no GarageNode": fbRole(fbRemoteID, fbRemZone, fbLocalUID),
		"no cluster-uid tag":                untagged,
		"import would rewrite tags":         noTier,
	}
	for name, staged := range cases {
		t.Run(name, func(t *testing.T) {
			layout := &garage.ClusterLayout{StagedRoleChanges: []garage.NodeRoleChange{staged}}
			_, err := r.garageNodeStagingIntent(context.Background(), cluster, layout, desired, fbPeers(t, fbLocalID, fbRemoteID))
			if err == nil || !strings.Contains(err.Error(), "is not an assignable live GarageNode") {
				t.Fatalf("err = %v, want refusal", err)
			}
		})
	}
}

// fbGarage is a minimal single-staging-area Garage that enforces the
// replication factor on Apply the way real Garage does (500 when fewer
// positive-capacity nodes than the factor would be in the new layout).
type fbGarage struct {
	mu      sync.Mutex
	up      []string // node IDs GetClusterStatus reports as up
	factor  int
	version int
	roles   map[string]garage.NodeRoleChange
	staged  map[string]garage.NodeRoleChange
	applies int
}

func (g *fbGarage) layout() garage.ClusterLayout {
	l := garage.ClusterLayout{Version: uint64(g.version)}
	for _, r := range g.roles {
		l.Roles = append(l.Roles, garage.LayoutNodeRole{ID: r.ID, Zone: r.Zone, Capacity: r.Capacity, Tags: r.Tags})
	}
	for _, r := range g.staged {
		l.StagedRoleChanges = append(l.StagedRoleChanges, r)
	}
	return l
}

func (g *fbGarage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/v2/GetClusterStatus":
		status := garage.ClusterStatus{}
		for _, id := range g.up {
			status.Nodes = append(status.Nodes, garage.NodeInfo{ID: id, IsUp: true})
		}
		_ = json.NewEncoder(w).Encode(status)
	case "/v2/GetClusterLayout":
		_ = json.NewEncoder(w).Encode(g.layout())
	case "/v2/UpdateClusterLayout":
		var req garage.UpdateClusterLayoutRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		for _, role := range req.Roles {
			g.staged[role.ID] = role
		}
		_ = json.NewEncoder(w).Encode(g.layout())
	case "/v2/ApplyClusterLayout":
		next := map[string]garage.NodeRoleChange{}
		for id, role := range g.roles {
			next[id] = role
		}
		for id, role := range g.staged {
			if role.Remove {
				delete(next, id)
			} else {
				next[id] = role
			}
		}
		storage := 0
		for _, role := range next {
			if role.Capacity != nil && *role.Capacity > 0 {
				storage++
			}
		}
		if storage < g.factor {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"code":"InternalError","message":"Internal error: The number of nodes with positive capacity (1) is smaller than the replication factor (2)."}`))
			return
		}
		g.roles, g.staged = next, map[string]garage.NodeRoleChange{}
		g.version++
		g.applies++
		_ = json.NewEncoder(w).Encode(g.layout())
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// TestGarageNodeFederatedBootstrap_CommitsBothSitesRoles drives the GarageNode
// staging transaction against a Garage that enforces RF=2: with the remote
// site's role already staged, the local GarageNode's stage+apply now commits
// both roles in one layout version instead of refusing.
func TestGarageNodeFederatedBootstrap_CommitsBothSitesRoles(t *testing.T) {
	cluster := fbCluster()
	r := fbReconciler(t, cluster)
	desired := fbRole(fbLocalID, fbLocalZone, fbLocalUID)
	remote := fbRole(fbRemoteID, fbRemZone, fbRemoteUID)
	g := &fbGarage{up: []string{fbLocalID, fbRemoteID}, factor: 2, roles: map[string]garage.NodeRoleChange{}, staged: map[string]garage.NodeRoleChange{remote.ID: remote}}
	srv := httptest.NewServer(g)
	defer srv.Close()
	client := garage.NewClient(srv.URL, "token")
	ctx := context.Background()

	layout, err := client.GetClusterLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	intended, err := r.garageNodeStagingIntent(ctx, cluster, layout, desired, client)
	if err != nil {
		t.Fatalf("staging intent: %v", err)
	}
	if _, err := stageAndApplyExclusiveLayout(ctx, client, layout, intended, nil, func() error {
		return client.UpdateClusterLayout(ctx, []garage.NodeRoleChange{desired})
	}); err != nil {
		t.Fatalf("stage+apply: %v", err)
	}
	if g.applies != 1 || g.version != 1 || len(g.roles) != 2 || len(g.staged) != 0 {
		t.Fatalf("applies=%d version=%d roles=%d staged=%d, want one apply committing both sites' roles",
			g.applies, g.version, len(g.roles), len(g.staged))
	}
	if got := g.roles[fbRemoteID]; got.Zone != fbRemZone || !nodeBelongsToClusterUID(got.Tags, fbRemoteUID) {
		t.Fatalf("remote role committed as %+v, want the remote site's exact staged role", got)
	}
}

// TestGarageNodeStagingIntent_PeerRoleNeedsBootstrapAndLivePeer: the exception
// applies only before any layout is committed and only to a node that is a live
// peer in this Garage's RPC mesh (which requires the shared RPC secret).
func TestGarageNodeStagingIntent_PeerRoleNeedsBootstrapAndLivePeer(t *testing.T) {
	cluster := fbCluster()
	r := fbReconciler(t, cluster)
	desired := fbRole(fbLocalID, fbLocalZone, fbLocalUID)
	remote := fbRole(fbRemoteID, fbRemZone, fbRemoteUID)
	cases := map[string]struct {
		version uint64
		client  *garage.Client
	}{
		"layout already committed": {version: 1, client: fbPeers(t, fbLocalID, fbRemoteID)},
		"peer not up":              {client: fbPeers(t, fbLocalID)},
		"no Garage client":         {},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			layout := &garage.ClusterLayout{Version: tc.version, StagedRoleChanges: []garage.NodeRoleChange{remote}}
			_, err := r.garageNodeStagingIntent(context.Background(), cluster, layout, desired, tc.client)
			if err == nil || !strings.Contains(err.Error(), "is not an assignable live GarageNode") {
				t.Fatalf("err = %v, want refusal", err)
			}
		})
	}
}
