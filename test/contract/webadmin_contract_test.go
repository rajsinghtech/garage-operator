//go:build garagecontract

package contract

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/garage-operator/internal/garage"
	"github.com/rajsinghtech/garage-operator/internal/garageversion"
)

// webAdminRelease is the first Garage release whose official images embed the
// web admin UI (Cargo feature "webadmin", upstream #1562).
var webAdminRelease = garageversion.Version{Major: 2, Minor: 6}

// webAdminHTTP does not follow redirects so the "/" -> "/ui/" redirect is
// observable.
var webAdminHTTP = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func webAdminGet(t *testing.T, nd *node, path, token string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+nd.adminAddr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := webAdminHTTP.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: read body: %v", path, err)
	}
	return resp, body
}

// selfNodeInfo reads the self node's version and compiled-in features.
func selfNodeInfo(t *testing.T, nd *node) (version string, features []string) {
	t.Helper()
	resp, body := webAdminGet(t, nd, "/v2/GetNodeInfo?node=self", adminToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetNodeInfo: status %d: %s", resp.StatusCode, body)
	}
	var out struct {
		Success map[string]struct {
			GarageVersion  string   `json:"garageVersion"`
			GarageFeatures []string `json:"garageFeatures"`
		} `json:"success"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("GetNodeInfo: %v: %s", err, body)
	}
	for _, info := range out.Success {
		return info.GarageVersion, info.GarageFeatures
	}
	t.Fatalf("GetNodeInfo: no node in response: %s", body)
	return "", nil
}

// The web admin UI shares the Admin API listener. Its static files are served
// without a token, while every Admin API call it makes still needs one. The
// operator publishes the admin port on the <cluster> Service and documents
// both facts (docs/how-to/web-admin.md), so a release that starts gating the
// UI, or stops gating /v2 behind it, must fail here.
func TestContract_WebAdminUIIsPublicAndAdminAPIStillNeedsToken(t *testing.T) {
	nd := startCluster(t, 1, 1)[0]

	// The Admin API refuses missing and wrong tokens on every release.
	for _, token := range []string{"", "not-the-admin-token"} {
		resp, body := webAdminGet(t, nd, "/v2/GetClusterStatus", token)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("GetClusterStatus with token %q: status %d, want 403: %s", token, resp.StatusCode, body)
		}
	}
	if resp, body := webAdminGet(t, nd, "/v2/GetClusterStatus", adminToken); resp.StatusCode != http.StatusOK {
		t.Fatalf("GetClusterStatus with the admin token: status %d: %s", resp.StatusCode, body)
	}

	version, features := selfNodeInfo(t, nd)
	hasUI := slices.Contains(features, "webadmin")
	if v, ok := garageversion.Parse(version); ok && v.AtLeast(webAdminRelease) && !hasUI {
		t.Fatalf("Garage %s from the official image lacks the webadmin feature (features: %v)", version, features)
	}
	if !hasUI {
		t.Skipf("Garage %s was built without the webadmin feature (features: %v)", version, features)
	}

	resp, _ := webAdminGet(t, nd, "/", "")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/ui/" {
		t.Fatalf("GET /: status %d Location %q, want 302 to /ui/", resp.StatusCode, resp.Header.Get("Location"))
	}
	// The SPA falls back to index.html for client-side routes.
	for _, path := range []string{"/ui/", "/ui/cluster"} {
		resp, body := webAdminGet(t, nd, path, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s without a token: status %d, want 200", path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("GET %s: Content-Type %q, want text/html", path, ct)
		}
		if !strings.Contains(string(body), "/ui/assets/") {
			t.Fatalf("GET %s: body does not reference /ui/assets/: %s", path, tail(string(body), 500))
		}
	}
}

// The operator sets the WebUIAvailable condition from one GetNodeInfo?node=*
// call: every node's garageFeatures must list "webadmin". The fan-out must
// answer for every node, carry the version and feature list, and agree with
// what each node reports about itself.
func TestContract_GetAllNodesBuildInfoReportsWebAdminFeature(t *testing.T) {
	nodes := startCluster(t, 2, 1)
	ctx := context.Background()
	a, b := nodes[0], nodes[1]
	if _, err := a.client.ConnectNode(ctx, b.id, b.rpcAddr); err != nil {
		t.Fatal(err)
	}
	assignAndApply(t, a, a.id, b.id)
	waitLayoutReady(t, a)

	var infos map[string]garage.NodeBuildInfo
	eventually(t, 30*time.Second, "GetNodeInfo?node=* answers for both nodes", func() (bool, string) {
		callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		got, nodeErr, err := a.client.GetAllNodesBuildInfo(callCtx)
		if err != nil {
			return false, err.Error()
		}
		if nodeErr != nil || len(got) != len(nodes) {
			return false, fmt.Sprintf("answers=%d nodeErr=%v", len(got), nodeErr)
		}
		infos = got
		return true, ""
	})

	for _, nd := range nodes {
		info, ok := infos[nd.id]
		if !ok {
			t.Fatalf("no answer for node %s: %+v", nd.id, infos)
		}
		version, features := selfNodeInfo(t, nd)
		if info.GarageVersion != version {
			t.Fatalf("node %s: fan-out version %q, self version %q", nd.id, info.GarageVersion, version)
		}
		if !slices.Equal(info.GarageFeatures, features) {
			t.Fatalf("node %s: fan-out features %v, self features %v", nd.id, info.GarageFeatures, features)
		}
		hasUI := slices.Contains(info.GarageFeatures, "webadmin")
		if v, ok := garageversion.Parse(version); ok && v.AtLeast(webAdminRelease) != hasUI {
			t.Fatalf("Garage %s: webadmin in features = %v, want %v (features: %v)",
				version, hasUI, v.AtLeast(webAdminRelease), info.GarageFeatures)
		}
	}
}
