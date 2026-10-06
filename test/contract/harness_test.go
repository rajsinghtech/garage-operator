//go:build garagecontract

// The contract tests pin the upstream behaviours the controllers rely on
// (staging semantics, error statuses, tombstones, alias conflicts) so a Garage
// release that changes one of them fails here instead of in a live cluster.
package contract

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const adminToken = "contract-admin-token-0123456789abcdef"

type node struct {
	client  *garage.Client
	id      string
	rpcAddr string
	s3Addr  string
	dir     string
	cmd     *exec.Cmd
}

// stop kills the node's Garage process (the cleanup tolerates a second kill).
func (n *node) stop(t *testing.T) {
	t.Helper()
	_ = n.cmd.Process.Kill()
	_, _ = n.cmd.Process.Wait()
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func garageBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("GARAGE_BIN")
	if bin == "" {
		t.Skip("GARAGE_BIN is not set")
	}
	return bin
}

// startCluster starts n independent Garage processes sharing one RPC secret.
// They are not connected to each other; tests call ConnectNode explicitly.
func startCluster(t *testing.T, n, replicationFactor int) []*node {
	t.Helper()
	bin := garageBin(t)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	rpcSecret := hex.EncodeToString(secret)
	nodes := make([]*node, 0, n)
	for i := 0; i < n; i++ {
		dir := t.TempDir()
		rpcPort, s3Port, adminPort := freePort(t), freePort(t), freePort(t)
		rpcAddr := fmt.Sprintf("127.0.0.1:%d", rpcPort)
		cfg := fmt.Sprintf(`metadata_dir = %q
data_dir = %q
db_engine = "sqlite"
replication_factor = %d
rpc_bind_addr = %q
rpc_public_addr = %q
rpc_secret = %q

[s3_api]
s3_region = "garage"
api_bind_addr = "127.0.0.1:%d"

[admin]
api_bind_addr = "127.0.0.1:%d"
admin_token = %q
`, filepath.Join(dir, "meta"), filepath.Join(dir, "data"), replicationFactor, rpcAddr, rpcAddr, rpcSecret, s3Port, adminPort, adminToken)
		cfgPath := filepath.Join(dir, "garage.toml")
		if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		logFile, err := os.Create(filepath.Join(dir, "garage.log"))
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "-c", cfgPath, "server")
		cmd.Stdout, cmd.Stderr = logFile, logFile
		cmd.Env = append(os.Environ(), "RUST_LOG=garage=warn")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		nd := &node{
			client:  garage.NewClient(fmt.Sprintf("http://127.0.0.1:%d", adminPort), adminToken),
			rpcAddr: rpcAddr, s3Addr: fmt.Sprintf("127.0.0.1:%d", s3Port), dir: dir, cmd: cmd,
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			_ = logFile.Close()
			if t.Failed() {
				if b, err := os.ReadFile(logFile.Name()); err == nil {
					t.Logf("garage node %s log:\n%s", rpcAddr, tail(string(b), 4000))
				}
			}
		})
		nodes = append(nodes, nd)
	}
	ctx := context.Background()
	for _, nd := range nodes {
		deadline := time.Now().Add(30 * time.Second)
		for {
			info, err := nd.client.GetSelfNodeInfo(ctx)
			if err == nil && info.NodeID != "" {
				nd.id = info.NodeID
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("garage at %s did not become ready: %v", nd.rpcAddr, err)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	return nodes
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func ptr[T any](v T) *T { return &v }

// storageRole is a staged storage assignment shaped like the operator's: Tags
// is always a non-nil slice (see TestContract_NullTagsAreRejected).
func storageRole(id, zone string, capacity uint64) garage.NodeRoleChange {
	return garage.NodeRoleChange{ID: id, Zone: zone, Capacity: ptr(capacity), Tags: []string{"contract"}}
}

// eventually polls cond every 250ms until it returns true or timeout elapses.
func eventually(t *testing.T, timeout time.Duration, what string, cond func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ok, detail := cond()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s: %s", timeout, what, detail)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// assignAndApply gives every node a storage role in zone "z1" and applies.
func assignAndApply(t *testing.T, nd *node, ids ...string) {
	t.Helper()
	ctx := context.Background()
	roles := make([]garage.NodeRoleChange, 0, len(ids))
	for _, id := range ids {
		roles = append(roles, storageRole(id, "z1", 1<<30))
	}
	if err := nd.client.UpdateClusterLayout(ctx, roles); err != nil {
		t.Fatalf("staging roles: %v", err)
	}
	if err := nd.client.ApplyStagedLayoutChanges(ctx); err != nil {
		t.Fatalf("applying roles: %v", err)
	}
}

// waitLayoutReady polls until a replicated table write works (layout gossip and
// table quorum are asynchronous after Apply).
func waitLayoutReady(t *testing.T, nd *node) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(60 * time.Second)
	for {
		_, err := nd.client.ListBuckets(ctx)
		if err == nil {
			h, herr := nd.client.GetClusterHealth(ctx)
			if herr == nil && h.Status == "healthy" {
				return
			}
			err = herr
		}
		if time.Now().After(deadline) {
			t.Fatalf("cluster never became ready: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func apiStatus(err error) int {
	var apiErr *garage.APIError
	if err == nil {
		return 0
	}
	if ok := asAPIError(err, &apiErr); ok {
		return apiErr.StatusCode
	}
	return -1
}

func asAPIError(err error, target **garage.APIError) bool {
	return errors.As(err, target)
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// wantStatus fails unless err is a Garage APIError with the given HTTP status.
func wantStatus(t *testing.T, what string, err error, status int) {
	t.Helper()
	if got := apiStatus(err); got != status {
		t.Fatalf("%s: want HTTP %d, got %d (%v)", what, status, got, err)
	}
}

// wantMessage fails unless err's Garage message contains substr (case-insensitive).
func wantMessage(t *testing.T, what string, err error, substr string) {
	t.Helper()
	var apiErr *garage.APIError
	if !asAPIError(err, &apiErr) || !strings.Contains(strings.ToLower(apiErr.GarageMessage()), strings.ToLower(substr)) {
		t.Fatalf("%s: want a Garage error containing %q, got %v", what, substr, err)
	}
}
