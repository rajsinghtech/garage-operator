package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Federation connect/import fault sweeps. Two fake Garage sites (layout +
// status + health + ConnectClusterNodes) sit behind #469 fault proxies and
// share a fakePeerWorld that decides which node IDs answer at which RPC
// address. connectToRemoteClusterWithLayout is driven exactly like
// reconcileFederationWithLayout does (fresh local status first), with one
// injected Admin API fault at every call position on either site, then clean
// retries. Every run must converge to the fault-free end state with exactly
// one import Apply, no leftover staging, and a quiescent steady state.

const (
	fedLocalID   = "1100000000000000000000000000000000000000000000000000000000000001"
	fedRemoteID  = "2200000000000000000000000000000000000000000000000000000000000002"
	fedLocalUID  = "fed-local-uid"
	fedRemoteUID = "fed-remote-uid"
	fedLocalZone = "z-local"
	fedZone      = "z-remote"
	fedOldAddr   = "10.20.0.2:3901"
	fedNewAddr   = "10.20.0.9:3901"
	fedTokenName = "remote-a-admin"
)

// fakePeerWorld is the shared network: nodeID -> the RPC address it answers on.
type fakePeerWorld struct {
	mu    sync.Mutex
	addrs map[string]string
}

func (w *fakePeerWorld) answers(id, addr string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.addrs[id] != "" && w.addrs[id] == addr
}

func (w *fakePeerWorld) move(id, addr string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.addrs[id] = addr
}

// fakeFederatedSite extends fakeGarageLayout with what federation needs: a
// status computed from the committed layout plus live peer connections, a
// health endpoint, and ConnectClusterNodes against the shared world.
type fakeFederatedSite struct {
	*fakeGarageLayout
	world     *fakePeerWorld
	selfID    string
	connected map[string]bool
	connects  []string
}

func newFakeFederatedSite(world *fakePeerWorld, selfID string, roles ...garage.LayoutNodeRole) *fakeFederatedSite {
	return &fakeFederatedSite{
		fakeGarageLayout: newFakeGarageLayout(roles...),
		world:            world,
		selfID:           selfID,
		connected:        map[string]bool{},
	}
}

func (s *fakeFederatedSite) server(t *testing.T) *httptest.Server {
	layoutSrv := s.fakeGarageLayout.server()
	t.Cleanup(layoutSrv.Close)
	layoutHandler := layoutSrv.Config.Handler
	mux := http.NewServeMux()
	mux.Handle("/", layoutHandler)
	mux.HandleFunc("/v2/GetClusterStatus", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(garage.ClusterStatus{LayoutVersion: s.version, Nodes: s.statusLocked()})
	})
	mux.HandleFunc("/v2/GetClusterHealth", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(garage.ClusterHealth{
			Status: healthStatusHealthy, KnownNodes: 1, ConnectedNodes: 1, StorageNodes: 1, StorageNodesUp: 1,
			Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256,
		})
	})
	mux.HandleFunc("/v2/ConnectClusterNodes", func(w http.ResponseWriter, r *http.Request) {
		var peers []string
		_ = json.NewDecoder(r.Body).Decode(&peers)
		results := make([]garage.ConnectNodeResult, 0, len(peers))
		for _, peer := range peers {
			id, addr, _ := strings.Cut(peer, "@")
			s.mu.Lock()
			s.connects = append(s.connects, peer)
			ok := s.world.answers(id, addr)
			if ok {
				s.connected[id] = true
			}
			s.mu.Unlock()
			if ok {
				results = append(results, garage.ConnectNodeResult{Success: true})
				continue
			}
			msg := "Error establishing RPC connection to remote node: " + peer
			results = append(results, garage.ConnectNodeResult{Success: false, Error: &msg})
		}
		_ = json.NewEncoder(w).Encode(results)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// statusLocked mirrors Garage: self is always up; every committed role and
// every connected peer is listed, up only while connected. Down peers carry
// no address (pinned by test/contract).
func (s *fakeFederatedSite) statusLocked() []garage.NodeInfo {
	ids := map[string]bool{s.selfID: true}
	for id := range s.roles {
		ids[id] = true
	}
	for id := range s.connected {
		ids[id] = true
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	nodes := make([]garage.NodeInfo, 0, len(sorted))
	for _, id := range sorted {
		n := garage.NodeInfo{ID: id, IsUp: id == s.selfID || s.connected[id]}
		if n.IsUp {
			// Up nodes report their RPC address (self: rpc_public_addr).
			s.world.mu.Lock()
			if addr := s.world.addrs[id]; addr != "" {
				n.Address = &addr
			}
			s.world.mu.Unlock()
		}
		if role, ok := s.roles[id]; ok {
			n.Role = &garage.NodeAssignedRole{Zone: role.Zone, Tags: append([]string(nil), role.Tags...), Capacity: role.Capacity}
		}
		nodes = append(nodes, n)
	}
	return nodes
}

func (s *fakeFederatedSite) disconnect(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.connected, id)
}

// remoteConnected reports whether the site holds a live connection to the
// remote storage node.
func (s *fakeFederatedSite) remoteConnected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connected[fedRemoteID]
}

func (s *fakeFederatedSite) connectCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.connects)
}

func fedCapacity() *uint64 { c := uint64(200 << 30); return &c }

func fedRemoteRole(addr string) garage.LayoutNodeRole {
	return garage.LayoutNodeRole{
		ID: fedRemoteID, Zone: fedZone, Capacity: fedCapacity(),
		Tags: append(buildNodeTags("gc", "remote-ns", tierStorage, nil, "gc-0", fedRemoteUID), nodeRPCAddressTagPrefix+addr),
	}
}

func fedLocalRole() garage.LayoutNodeRole {
	return garage.LayoutNodeRole{
		ID: fedLocalID, Zone: fedLocalZone, Capacity: fedCapacity(),
		Tags: buildNodeTags("gc", "tenant", tierStorage, nil, "gc-0", fedLocalUID),
	}
}

type fedEnv struct {
	r            *GarageClusterReconciler
	cluster      *garagev1beta2.GarageCluster
	world        *fakePeerWorld
	local        *fakeFederatedSite
	remote       *fakeFederatedSite
	localProxy   *faultProxy
	remoteProxy  *faultProxy
	localClient  *garage.Client
	remoteConfig garagev1beta2.RemoteClusterConfig
}

// newFedEnv builds two sites. The remote site has its storage node committed
// at remoteAddr; the world answers for it at worldAddr. When imported is set
// the local layout already holds the remote role (as imported earlier, with
// the address tag it had then).
func newFedEnv(t *testing.T, remoteAddr, worldAddr string, imported bool, stagedOnly ...bool) *fedEnv {
	t.Helper()
	world := &fakePeerWorld{addrs: map[string]string{fedRemoteID: worldAddr, fedLocalID: "10.10.0.1:3901"}}
	localRoles := []garage.LayoutNodeRole{fedLocalRole()}
	if imported {
		role := fedRemoteRole(fedOldAddr)
		role.Tags = remoteImportTags(garagev1beta2.RemoteClusterConfig{}, "", role.Capacity, role.Tags)
		localRoles = append(localRoles, role)
	}
	local := newFakeFederatedSite(world, fedLocalID, localRoles...)
	remote := newFakeFederatedSite(world, fedRemoteID, fedRemoteRole(remoteAddr))
	if len(stagedOnly) > 0 && stagedOnly[0] {
		// The remote controller staged its node but has not applied yet (the
		// bootstrap race the staged-role import path exists for).
		role := fedRemoteRole(remoteAddr)
		remote.roles = map[string]garage.LayoutNodeRole{}
		remote.staged = []garage.NodeRoleChange{{ID: role.ID, Zone: role.Zone, Capacity: role.Capacity, Tags: role.Tags}}
	}
	localProxy := newFaultProxy(t, local.server(t).URL)
	remoteProxy := newFaultProxy(t, remote.server(t).URL)

	remoteConfig := garagev1beta2.RemoteClusterConfig{
		Name: "remote-a", Zone: fedZone,
		Connection: garagev1beta2.RemoteClusterConnection{
			AdminAPIEndpoint:    remoteProxy.srv.URL,
			AdminTokenSecretRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: fedTokenName}},
		},
	}
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "gc", Namespace: "tenant", UID: types.UID(fedLocalUID)},
		Spec:       garagev1beta2.GarageClusterSpec{Zone: fedLocalZone, RemoteClusters: []garagev1beta2.RemoteClusterConfig{remoteConfig}},
	}
	kube := fake.NewClientBuilder().WithScheme(testSchemeForFault(t)).WithObjects(
		cluster,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: fedTokenName, Namespace: "tenant"},
			Data:       map[string][]byte{DefaultAdminTokenKey: []byte("remote-token")},
		},
	).Build()
	return &fedEnv{
		r: &GarageClusterReconciler{
			Client: kube, EventRecorder: record.NewFakeRecorder(64),
			LayoutMutations: NewLayoutMutationCoordinator(),
		},
		cluster: cluster, world: world, local: local, remote: remote,
		localProxy: localProxy, remoteProxy: remoteProxy,
		localClient:  garage.NewClient(localProxy.srv.URL, "local-token"),
		remoteConfig: remoteConfig,
	}
}

// reconcileOnce mirrors reconcileFederationWithLayout for one remote: a fresh
// local status read, then the connect/import pass.
func (e *fedEnv) reconcileOnce(ctx context.Context) error {
	status, err := e.localClient.GetClusterStatus(ctx)
	if err != nil {
		return fmt.Errorf("local status: %w", err)
	}
	return e.r.connectToRemoteClusterWithLayout(ctx, e.cluster, e.localClient, status, e.remoteConfig, true)
}

func (e *fedEnv) arm(p *faultProxy, failAt int, after bool) {
	for _, q := range []*faultProxy{e.localProxy, e.remoteProxy} {
		q.mu.Lock()
		q.failAt, q.after, q.hit, q.calls, q.methods = 0, false, false, 0, nil
		q.mu.Unlock()
	}
	if p == nil {
		return
	}
	p.mu.Lock()
	p.failAt, p.after = failAt, after
	p.mu.Unlock()
}

func (e *fedEnv) disarm() { e.arm(nil, 0, false) }

func proxyStats(p *faultProxy) (calls int, hit bool, writes []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range p.methods {
		if strings.Contains(m, "UpdateClusterLayout") || strings.Contains(m, "ApplyClusterLayout") || strings.Contains(m, "RevertClusterLayout") {
			writes = append(writes, m)
		}
	}
	return p.calls, p.hit, writes
}

type fedScenario struct {
	name                 string
	remoteAddr           string // address tag in the remote site's committed role
	worldAddr            string // where the remote node actually answers
	imported             bool   // local layout already holds the remote role
	stagedOnly           bool   // the remote role is only staged on the remote site
	wantImportApplies    int    // import Applies expected on the local site
	wantConnectedAddress string
}

func fedScenarios() []fedScenario {
	return []fedScenario{
		{
			name: "bootstrap connect and import", remoteAddr: fedOldAddr, worldAddr: fedOldAddr,
			wantImportApplies: 1, wantConnectedAddress: fedOldAddr,
		},
		{
			// The remote pod moved while the regions were disconnected: the local
			// layout still carries the old rpc-address tag, the remote layout has
			// the new one. Reconnect must refresh from the remote layout.
			name: "reconnect after remote address change", remoteAddr: fedNewAddr, worldAddr: fedNewAddr, imported: true,
			wantImportApplies: 0, wantConnectedAddress: fedNewAddr,
		},
		{
			// No committed remote role yet: the remote status has no role for
			// its node, so the import must use the remote's staged role and the
			// connect must use the address the remote reports for itself.
			name: "bootstrap import of a remote role that is only staged", remoteAddr: fedOldAddr, worldAddr: fedOldAddr,
			stagedOnly: true, wantImportApplies: 1, wantConnectedAddress: fedOldAddr,
		},
	}
}

// fedEndState is what the sweep compares against the fault-free baseline.
func fedEndState(e *fedEnv) string {
	return fmt.Sprintf("%s connected=%v", layoutSnapshot(e.local.fakeGarageLayout), e.local.remoteConnected())
}

func TestFaultSweep_FederationConnectAndImport(t *testing.T) {
	for _, sc := range fedScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			ctx := context.Background()

			base := newFedEnv(t, sc.remoteAddr, sc.worldAddr, sc.imported, sc.stagedOnly)
			base.disarm()
			if err := base.reconcileOnce(ctx); err != nil {
				t.Fatalf("baseline: %v", err)
			}
			want := fedEndState(base)
			if !base.local.remoteConnected() || !base.local.hasRole(fedRemoteID) {
				t.Fatalf("baseline did not connect and import: %s", want)
			}
			if got := len(base.local.appliedChanges()); got != sc.wantImportApplies {
				t.Fatalf("baseline import applies = %d, want %d", got, sc.wantImportApplies)
			}
			localCalls, _, _ := proxyStats(base.localProxy)
			remoteCalls, _, _ := proxyStats(base.remoteProxy)
			assertFedQuiescent(t, base, "baseline")

			type side struct {
				name  string
				proxy func(*fedEnv) *faultProxy
				calls int
			}
			sides := []side{
				{"local", func(e *fedEnv) *faultProxy { return e.localProxy }, localCalls},
				{"remote", func(e *fedEnv) *faultProxy { return e.remoteProxy }, remoteCalls},
			}
			runs, hits := 0, 0
			defer func() { t.Logf("%d single-fault runs, %d injected", runs, hits) }()
			for _, sd := range sides {
				for pos := 1; pos <= sd.calls+1; pos++ {
					for _, after := range []bool{false, true} {
						label := fmt.Sprintf("%s fault at call %d (after=%v)", sd.name, pos, after)
						e := newFedEnv(t, sc.remoteAddr, sc.worldAddr, sc.imported, sc.stagedOnly)
						e.arm(sd.proxy(e), pos, after)
						firstErr := e.reconcileOnce(ctx)
						_, hit, _ := proxyStats(sd.proxy(e))
						runs++
						if hit {
							hits++
						}
						e.disarm()
						var retryErr error
						for i := 0; i < 3 && fedEndState(e) != want; i++ {
							retryErr = e.reconcileOnce(ctx)
						}
						if got := fedEndState(e); got != want {
							t.Fatalf("%s (hit=%v, first err=%v, retry err=%v): end state diverged\n got: %s\nwant: %s",
								label, hit, firstErr, retryErr, got, want)
						}
						if got := len(e.local.appliedChanges()); got != sc.wantImportApplies {
							t.Fatalf("%s: %d import applies, want exactly %d (a duplicate or lost import)", label, got, sc.wantImportApplies)
						}
						if hasConnectTo(e.local, fedRemoteID, sc.wantConnectedAddress) == 0 {
							t.Fatalf("%s: never connected at %s", label, sc.wantConnectedAddress)
						}
						assertFedQuiescent(t, e, label)
					}
				}
			}
			if testing.Short() {
				return
			}
			// Double faults: one on each site in the same reconcile.
			for lp := 1; lp <= localCalls; lp++ {
				for rp := 1; rp <= remoteCalls; rp++ {
					for _, after := range []bool{false, true} {
						label := fmt.Sprintf("double fault local@%d remote@%d (after=%v)", lp, rp, after)
						e := newFedEnv(t, sc.remoteAddr, sc.worldAddr, sc.imported, sc.stagedOnly)
						e.arm(e.localProxy, lp, after)
						e.remoteProxy.mu.Lock()
						e.remoteProxy.failAt, e.remoteProxy.after = rp, after
						e.remoteProxy.mu.Unlock()
						firstErr := e.reconcileOnce(ctx)
						e.disarm()
						for i := 0; i < 3 && fedEndState(e) != want; i++ {
							_ = e.reconcileOnce(ctx)
						}
						if got := fedEndState(e); got != want {
							t.Fatalf("%s (first err=%v): end state diverged\n got: %s\nwant: %s", label, firstErr, got, want)
						}
						if got := len(e.local.appliedChanges()); got != sc.wantImportApplies {
							t.Fatalf("%s: %d import applies, want exactly %d", label, got, sc.wantImportApplies)
						}
						assertFedQuiescent(t, e, label)
					}
				}
			}
		})
	}
}

// assertFedQuiescent checks that a converged pair does no further layout
// writes or reconnects.
func assertFedQuiescent(t *testing.T, e *fedEnv, label string) {
	t.Helper()
	e.disarm()
	connectsBefore := e.local.connectCount()
	if err := e.reconcileOnce(context.Background()); err != nil {
		t.Fatalf("%s: steady-state reconcile: %v", label, err)
	}
	_, _, localWrites := proxyStats(e.localProxy)
	_, _, remoteWrites := proxyStats(e.remoteProxy)
	if len(localWrites) != 0 || len(remoteWrites) != 0 {
		t.Fatalf("%s: steady state still writes the layout: local=%v remote=%v", label, localWrites, remoteWrites)
	}
	if e.local.connectCount() != connectsBefore {
		t.Fatalf("%s: steady state redialed a connected peer", label)
	}
	e.local.mu.Lock()
	staged := len(e.local.staged)
	e.local.mu.Unlock()
	if staged != 0 {
		t.Fatalf("%s: staging not empty at steady state", label)
	}
}

func hasConnectTo(s *fakeFederatedSite, id, addr string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.connects {
		if c == id+"@"+addr {
			n++
		}
	}
	return n
}

// A remote Admin API that stays unreachable must not touch the local layout,
// and the pair must converge once it comes back.
func TestFederationRemoteUnreachableLeavesLocalLayoutUntouched(t *testing.T) {
	ctx := context.Background()
	e := newFedEnv(t, fedOldAddr, fedOldAddr, false)
	pristine := fedEndState(e)
	reachable := e.remoteConfig.Connection.AdminAPIEndpoint
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream connect error", http.StatusServiceUnavailable)
	}))
	defer down.Close()
	for _, endpoint := range []string{"http://127.0.0.1:1", down.URL} {
		e.remoteConfig.Connection.AdminAPIEndpoint = endpoint
		for i := 0; i < 2; i++ {
			if err := e.reconcileOnce(ctx); err == nil {
				t.Fatalf("an unreachable remote (%s) must surface an error", endpoint)
			}
		}
	}
	if got := fedEndState(e); got != pristine {
		t.Fatalf("an unreachable remote changed local state:\n got: %s\nwant: %s", got, pristine)
	}
	if e.local.connectCount() != 0 {
		t.Fatal("dialed peers without any remote node knowledge")
	}
	e.remoteConfig.Connection.AdminAPIEndpoint = reachable
	if err := e.reconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if !e.local.hasRole(fedRemoteID) || !e.local.remoteConnected() {
		t.Fatalf("did not converge after the remote came back: %s", fedEndState(e))
	}
}

// After import, losing the RPC connection is repaired by reconnecting without
// any further layout write, and a remote node that is down everywhere is not
// re-imported or removed.
func TestFederationReconnectsWithoutLayoutWrites(t *testing.T) {
	ctx := context.Background()
	e := newFedEnv(t, fedOldAddr, fedOldAddr, false)
	e.disarm()
	if err := e.reconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	applies := len(e.local.appliedChanges())

	e.local.disconnect(fedRemoteID)
	e.disarm()
	if err := e.reconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if !e.local.remoteConnected() {
		t.Fatal("lost connection was not repaired")
	}
	if _, _, writes := proxyStats(e.localProxy); len(writes) != 0 {
		t.Fatalf("reconnect wrote the layout: %v", writes)
	}

	// The node dies: nothing answers any more.
	e.local.disconnect(fedRemoteID)
	e.world.move(fedRemoteID, "")
	for i := 0; i < 2; i++ {
		e.disarm()
		_ = e.reconcileOnce(ctx)
	}
	if !e.local.hasRole(fedRemoteID) || len(e.local.appliedChanges()) != applies {
		t.Fatalf("a dead remote node must keep its imported role and cause no layout writes: %s", fedEndState(e))
	}
}
