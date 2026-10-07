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
	"sort"
	"strings"
	"sync"
	"time"

	"k8s.io/utils/ptr"

	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// redundancyGarage models the parts of a Garage cluster the full-redundancy
// proof reads and drives: worker lists with stable IDs, full table syncs, and
// blocks repair workers. Each tick advances background work by one step.
type redundancyGarage struct {
	mu sync.Mutex
	// repairsAlwaysFail keeps repairErrors for every later repair too.
	repairsAlwaysFail bool

	layoutVersion uint64
	staged        bool
	nodes         []*redundancyGarageNode
	blockErrors   map[string][]garage.BlockError

	// syncTicks is how many ticks a full table sync stays busy.
	syncTicks int
	// repairTicks is how many ticks a blocks repair runs.
	repairTicks int
	// repairErrors makes the next blocks repair on a node finish with errors.
	repairErrors map[string]uint64

	tablesLaunches map[string]int
	blocksLaunches map[string]int
}

type redundancyGarageNode struct {
	id      string
	up      bool
	nextID  uint64
	workers []garage.WorkerInfo
	// syncLeft counts down the busy ticks of the current full table sync.
	syncLeft int
	// repairLeft maps a repair worker ID to its remaining busy ticks.
	repairLeft map[uint64]int
	// workersFail makes ListWorkers report an error for this node.
	workersFail bool
	// startupSyncAt mirrors Garage's own full table sync 20 s after
	// process start (zero: none pending).
	startupSyncAt time.Time
	// syncsDone and repairsDone count finished full table syncs and blocks
	// repairs, so tests can assert that a proof really ran them.
	syncsDone, repairsDone int
}

func redundancyNodeID(i int) string {
	return fmt.Sprintf("%064x", 0xa000+i)
}

func newRedundancyGarage(storageNodes int) *redundancyGarage {
	g := &redundancyGarage{
		layoutVersion:  3,
		blockErrors:    map[string][]garage.BlockError{},
		syncTicks:      1,
		repairTicks:    1,
		repairErrors:   map[string]uint64{},
		tablesLaunches: map[string]int{},
		blocksLaunches: map[string]int{},
	}
	for i := 0; i < storageNodes; i++ {
		node := &redundancyGarageNode{id: redundancyNodeID(i), up: true}
		node.boot()
		g.nodes = append(g.nodes, node)
	}
	return g
}

// boot (re)creates the worker set a freshly started Garage process has.
// restart simulates a Garage process restart at now: worker IDs restart from
// one with zero counters, and running syncs and repairs are lost.
func (g *redundancyGarage) restart(i int, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[i].boot()
	g.nodes[i].startupSyncAt = now.Add(20 * time.Second)
}

func (n *redundancyGarageNode) boot() {
	n.nextID = 0
	n.workers = nil
	n.syncLeft = 0
	n.repairLeft = map[uint64]int{}
	add := func(name string) {
		n.nextID++
		n.workers = append(n.workers, garage.WorkerInfo{
			ID: n.nextID, Name: name, State: garage.WorkerState{State: "idle"},
			QueueLength: ptr.To(uint64(0)), Freeform: []string{},
		})
	}
	n.nextID++
	n.workers = append(n.workers, garage.WorkerInfo{
		ID: n.nextID, Name: "Block resync worker #1", State: garage.WorkerState{State: "idle"},
		QueueLength: ptr.To(uint64(0)), PersistentErrors: ptr.To(uint64(0)), Freeform: []string{},
	})
	for _, table := range []string{"admin_token", "block_ref", "bucket_alias", "bucket_v2", "key", "object", "version"} {
		add(table + " sync")
		add(table + " Merkle")
		add(table + " queue")
	}
}

func (n *redundancyGarageNode) worker(name string) *garage.WorkerInfo {
	for i := range n.workers {
		if n.workers[i].Name == name {
			return &n.workers[i]
		}
	}
	return nil
}

func (g *redundancyGarage) node(id string) *redundancyGarageNode {
	for _, node := range g.nodes {
		if node.id == id {
			return node
		}
	}
	return nil
}

func (g *redundancyGarage) launch(nodeID, repairType string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	node := g.node(nodeID)
	if node == nil || !node.up {
		return fmt.Errorf("node %s unavailable", shortID(nodeID))
	}
	switch strings.ToLower(repairType) {
	case "tables":
		g.tablesLaunches[nodeID]++
		node.syncLeft = g.syncTicks
		for _, table := range redundancyMetadataTables {
			worker := node.worker(table + " sync")
			worker.State = garage.WorkerState{State: "busy"}
			worker.QueueLength = ptr.To(uint64(128))
		}
	case "blocks":
		g.blocksLaunches[nodeID]++
		node.nextID++
		node.workers = append(node.workers, garage.WorkerInfo{
			ID: node.nextID, Name: blockRepairWorkerName, State: garage.WorkerState{State: "busy"},
			Progress: ptr.To("0.00%"), Freeform: []string{},
		})
		node.repairLeft[node.nextID] = g.repairTicks
	default:
		return fmt.Errorf("unsupported repair %q", repairType)
	}
	return nil
}

// tick advances every running sync and repair by one step, at time now.
func (g *redundancyGarage) tick(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, node := range g.nodes {
		if !node.up {
			continue
		}
		if node.syncLeft > 0 {
			node.syncLeft--
			if node.syncLeft == 0 {
				node.syncsDone++
			}
			for _, table := range redundancyMetadataTables {
				worker := node.worker(table + " sync")
				if node.syncLeft == 0 {
					worker.State = garage.WorkerState{State: "idle"}
					worker.QueueLength = ptr.To(uint64(0))
				} else {
					worker.QueueLength = ptr.To(*worker.QueueLength / 2)
				}
			}
		}
		for id, left := range node.repairLeft {
			worker := workerByID(node.workers, id)
			if left > 1 {
				node.repairLeft[id] = left - 1
				worker.Progress = ptr.To("50.00%")
				continue
			}
			delete(node.repairLeft, id)
			node.repairsDone++
			worker.State = garage.WorkerState{State: "done"}
			worker.Progress = nil
			worker.Errors = g.repairErrors[node.id]
			if !g.repairsAlwaysFail {
				delete(g.repairErrors, node.id)
			}
		}
		if !node.startupSyncAt.IsZero() && !now.Before(node.startupSyncAt) {
			node.startupSyncAt = time.Time{}
			node.syncLeft = max(g.syncTicks, 1)
			for _, table := range redundancyMetadataTables {
				worker := node.worker(table + " sync")
				worker.State = garage.WorkerState{State: "busy"}
				worker.QueueLength = ptr.To(uint64(128))
			}
		}
	}
}

func (g *redundancyGarage) health() *garage.ClusterHealth {
	up := 0
	for _, node := range g.nodes {
		if node.up {
			up++
		}
	}
	allOK := 256
	if up < len(g.nodes) {
		allOK = 0
	}
	return &garage.ClusterHealth{
		Status: "healthy", KnownNodes: len(g.nodes), ConnectedNodes: up,
		StorageNodes: len(g.nodes), StorageNodesUp: up,
		Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: allOK,
	}
}

func (g *redundancyGarage) clusterStatus() *garage.ClusterStatus {
	status := &garage.ClusterStatus{LayoutVersion: g.layoutVersion}
	for _, node := range g.nodes {
		status.Nodes = append(status.Nodes, garage.NodeInfo{
			ID: node.id, IsUp: node.up,
			Role: &garage.NodeAssignedRole{Zone: "z1", Tags: []string{}, Capacity: ptr.To(uint64(1 << 30))},
		})
	}
	return status
}

func (g *redundancyGarage) history() *garage.LayoutHistoryResponse {
	return &garage.LayoutHistoryResponse{
		CurrentVersion: g.layoutVersion, MinAck: g.layoutVersion,
		Versions: []garage.LayoutVersion{{
			Version: g.layoutVersion, Status: garage.LayoutVersionStatusCurrent, StorageNodes: len(g.nodes),
		}},
	}
}

func (g *redundancyGarage) layout() *garage.ClusterLayout {
	layout := &garage.ClusterLayout{Version: g.layoutVersion, PartitionSize: 1, StagedRoleChanges: []garage.NodeRoleChange{}}
	for _, node := range g.nodes {
		layout.Roles = append(layout.Roles, garage.LayoutNodeRole{ID: node.id, Zone: "z1", Capacity: ptr.To(uint64(1 << 30)), Tags: []string{}})
	}
	if g.staged {
		layout.StagedRoleChanges = append(layout.StagedRoleChanges, garage.NodeRoleChange{ID: g.nodes[0].id})
	}
	return layout
}

func (g *redundancyGarage) listWorkers() *garage.ListWorkersResponse {
	out := &garage.ListWorkersResponse{Success: map[string][]garage.WorkerInfo{}, Error: map[string]string{}}
	for _, node := range g.nodes {
		if !node.up || node.workersFail {
			out.Error[node.id] = "node unavailable"
			continue
		}
		workers := make([]garage.WorkerInfo, len(node.workers))
		copy(workers, node.workers)
		out.Success[node.id] = workers
	}
	return out
}

func (g *redundancyGarage) listBlockErrors() *garage.ListBlockErrorsResponse {
	out := &garage.ListBlockErrorsResponse{Success: map[string][]garage.BlockError{}, Error: map[string]string{}}
	for _, node := range g.nodes {
		if !node.up {
			out.Error[node.id] = "node unavailable"
			continue
		}
		out.Success[node.id] = append([]garage.BlockError{}, g.blockErrors[node.id]...)
	}
	return out
}

// input builds a full observation for advanceRedundancy.
func (g *redundancyGarage) input() redundancyInput {
	g.mu.Lock()
	defer g.mu.Unlock()
	return redundancyInput{
		Observed:    true,
		Health:      g.health(),
		Status:      g.clusterStatus(),
		History:     g.history(),
		Layout:      g.layout(),
		Workers:     g.listWorkers(),
		BlockErrors: g.listBlockErrors(),
	}
}

func (g *redundancyGarage) totalLaunches() (tables, blocks int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, count := range g.tablesLaunches {
		tables += count
	}
	for _, count := range g.blocksLaunches {
		blocks += count
	}
	return tables, blocks
}

// serveHTTP exposes the model as the Garage Admin API subset the status pass
// and the proof use. It returns false for paths it does not handle.
func (g *redundancyGarage) serveHTTP(r *http.Request) (int, any, bool) {
	switch r.URL.Path {
	case "/v2/GetClusterHealth":
		g.mu.Lock()
		defer g.mu.Unlock()
		return http.StatusOK, g.health(), true
	case "/v2/GetClusterStatus":
		g.mu.Lock()
		defer g.mu.Unlock()
		return http.StatusOK, g.clusterStatus(), true
	case "/v2/GetClusterLayoutHistory":
		g.mu.Lock()
		defer g.mu.Unlock()
		return http.StatusOK, g.history(), true
	case "/v2/GetClusterLayout":
		g.mu.Lock()
		defer g.mu.Unlock()
		return http.StatusOK, g.layout(), true
	case "/v2/ListWorkers":
		g.mu.Lock()
		defer g.mu.Unlock()
		return http.StatusOK, g.listWorkers(), true
	case "/v2/ListBlockErrors":
		g.mu.Lock()
		defer g.mu.Unlock()
		return http.StatusOK, g.listBlockErrors(), true
	case "/v2/LaunchRepairOperation":
		var body struct {
			RepairType string `json:"repairType"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return http.StatusBadRequest, map[string]string{"message": err.Error()}, true
		}
		nodeID := r.URL.Query().Get("node")
		if err := g.launch(nodeID, body.RepairType); err != nil {
			return http.StatusOK, map[string]any{"success": map[string]any{}, "error": map[string]string{nodeID: err.Error()}}, true
		}
		return http.StatusOK, map[string]any{"success": map[string]any{nodeID: nil}, "error": map[string]string{}}, true
	}
	return 0, nil, false
}

func sortedLaunchKeys(launches []redundancyLaunch) []string {
	out := make([]string, 0, len(launches))
	for _, launch := range launches {
		out = append(out, shortID(launch.NodeID)+":"+launch.RepairType)
	}
	sort.Strings(out)
	return out
}
