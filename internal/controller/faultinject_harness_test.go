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

// Fault-injection harness: a stateful in-memory Garage Admin API plus a
// Kubernetes client interceptor that can fail the Nth write. Scenarios built on
// top of it run a reconcile with one injected fault at every write position and
// then require that fault-free retries converge to the same end state as an
// uninterrupted run (no duplicate/leaked Garage objects, no wedged state).

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

	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// ---------------------------------------------------------------------------
// Stateful fake Garage Admin API
// ---------------------------------------------------------------------------

type fgKey struct {
	ID, Secret, Name string
	CreateBucket     bool
}

type fgBucket struct {
	ID      string
	Aliases map[string]bool
	// perms maps access key ID -> permissions on this bucket.
	Perms   map[string]garage.BucketKeyPerms
	Website *garage.UpdateBucketWebsiteAccess
	Quotas  *garage.BucketQuotas
}

// garageFault describes an injected Admin API fault on the Nth request.
type garageFault struct {
	At int
	// AfterCommit applies the mutation and then reports a server error, i.e.
	// the response is lost after the write committed.
	AfterCommit bool
}

type fakeGarage struct {
	mu         sync.Mutex
	keys       map[string]*fgKey
	tombstones map[string]bool
	buckets    map[string]*fgBucket
	nextID     int
	calls      int
	mutations  int
	fault      *garageFault
	faultHit   bool
	trace      []string
	server     *httptest.Server
	// extra serves Admin API paths this fake does not model itself, and
	// extraSnapshot appends that state to snapshot.
	extra         func(r *http.Request) (status int, body any, handled bool)
	extraSnapshot func() string
}

func newFakeGarage(t *testing.T) *fakeGarage {
	t.Helper()
	g := &fakeGarage{
		keys:       map[string]*fgKey{},
		tombstones: map[string]bool{},
		buckets:    map[string]*fgBucket{},
	}
	g.server = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.server.Close)
	return g
}

func (g *fakeGarage) url() string { return g.server.URL }

func isMutation(path string) bool {
	switch path {
	case "/v2/CreateKey", "/v2/ImportKey", "/v2/UpdateKey", "/v2/DeleteKey",
		"/v2/CreateBucket", "/v2/UpdateBucket", "/v2/DeleteBucket",
		"/v2/AddBucketAlias", "/v2/RemoveBucketAlias",
		"/v2/AllowBucketKey", "/v2/DenyBucketKey",
		"/v2/LaunchRepairOperation":
		return true
	}
	return false
}

type fgResp struct {
	status int
	body   any
}

func (g *fakeGarage) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	mut := isMutation(r.URL.Path)
	if mut {
		g.mutations++
	}
	g.trace = append(g.trace, fmt.Sprintf("%s?%s", r.URL.Path, r.URL.RawQuery))

	hit := g.fault != nil && g.calls == g.fault.At
	if hit {
		g.faultHit = true
	}
	if hit && !g.fault.AfterCommit {
		http.Error(w, "injected fault", http.StatusInternalServerError)
		return
	}
	resp := g.handle(r)
	if hit {
		// Mutation (if any) already applied; the response is lost.
		http.Error(w, "injected fault after commit", http.StatusInternalServerError)
		return
	}
	if resp.status == 0 {
		resp.status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.status)
	if resp.body != nil {
		_ = json.NewEncoder(w).Encode(resp.body)
	}
}

func (g *fakeGarage) newID() string {
	g.nextID++
	return fmt.Sprintf("%064x", g.nextID)
}

func (g *fakeGarage) keyView(k *fgKey, secret bool) garage.Key {
	out := garage.Key{AccessKeyID: k.ID, Name: k.Name, Permissions: garage.KeyPermissions{CreateBucket: k.CreateBucket}, Buckets: []garage.KeyBucket{}}
	if secret {
		out.SecretAccessKey = k.Secret
	}
	ids := make([]string, 0, len(g.buckets))
	for id := range g.buckets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		b := g.buckets[id]
		if p, ok := b.Perms[k.ID]; ok {
			out.Buckets = append(out.Buckets, garage.KeyBucket{ID: id, GlobalAliases: sortedAliases(b), LocalAliases: []string{}, Permissions: p})
		}
	}
	return out
}

func sortedAliases(b *fgBucket) []string {
	out := make([]string, 0, len(b.Aliases))
	for a := range b.Aliases {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

func (g *fakeGarage) bucketView(b *fgBucket) garage.Bucket {
	out := garage.Bucket{ID: b.ID, GlobalAliases: sortedAliases(b), Keys: []garage.BucketKeyInfo{}, Quotas: b.Quotas}
	if b.Quotas == nil {
		out.Quotas = &garage.BucketQuotas{}
	}
	if b.Website != nil && b.Website.Enabled {
		out.WebsiteAccess = true
		out.WebsiteConfig = &garage.WebsiteConfig{IndexDocument: b.Website.IndexDocument, ErrorDocument: b.Website.ErrorDocument}
	}
	ids := make([]string, 0, len(b.Perms))
	for id := range b.Perms {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		name := ""
		if k := g.keys[id]; k != nil {
			name = k.Name
		}
		out.Keys = append(out.Keys, garage.BucketKeyInfo{AccessKeyID: id, Name: name, Permissions: b.Perms[id]})
	}
	return out
}

func (g *fakeGarage) findBucket(q map[string][]string) *fgBucket {
	if v := q["id"]; len(v) > 0 {
		return g.buckets[v[0]]
	}
	if v := q["globalAlias"]; len(v) > 0 {
		for _, b := range g.buckets {
			if b.Aliases[v[0]] {
				return b
			}
		}
		return nil
	}
	if v := q["search"]; len(v) > 0 {
		for _, b := range g.buckets {
			if strings.HasPrefix(b.ID, v[0]) || b.Aliases[v[0]] {
				return b
			}
		}
	}
	return nil
}

func (g *fakeGarage) handle(r *http.Request) fgResp {
	q := r.URL.Query()
	notFound := fgResp{status: http.StatusNotFound, body: map[string]string{"message": "not found"}}
	switch r.URL.Path {
	case "/v2/ListKeys":
		out := make([]garage.KeyListItem, 0, len(g.keys))
		for _, k := range g.keys {
			out = append(out, garage.KeyListItem{ID: k.ID, Name: k.Name})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		return fgResp{body: out}
	case "/v2/GetKeyInfo":
		k := g.keys[q.Get("id")]
		if k == nil && q.Get("search") != "" {
			for _, c := range g.keys {
				if c.Name == q.Get("search") || strings.HasPrefix(c.ID, q.Get("search")) {
					k = c
				}
			}
		}
		if k == nil {
			return notFound
		}
		return fgResp{body: g.keyView(k, q.Get("showSecretKey") == "true")}
	case "/v2/CreateKey":
		var req garage.CreateKeyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		k := &fgKey{ID: "GK" + g.newID()[:24], Secret: g.newID(), Name: req.Name}
		g.keys[k.ID] = k
		return fgResp{body: g.keyView(k, true)}
	case "/v2/ImportKey":
		var req garage.ImportKeyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if g.keys[req.AccessKeyID] != nil || g.tombstones[req.AccessKeyID] {
			return fgResp{status: http.StatusConflict, body: map[string]string{"message": "key exists"}}
		}
		k := &fgKey{ID: req.AccessKeyID, Secret: req.SecretAccessKey, Name: req.Name}
		g.keys[k.ID] = k
		return fgResp{body: g.keyView(k, true)}
	case "/v2/UpdateKey":
		k := g.keys[q.Get("id")]
		if k == nil {
			return notFound
		}
		var body garage.UpdateKeyRequestBody
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Name != "" {
			k.Name = body.Name
		}
		if body.Allow != nil && body.Allow.CreateBucket {
			k.CreateBucket = true
		}
		if body.Deny != nil && body.Deny.CreateBucket {
			k.CreateBucket = false
		}
		return fgResp{body: g.keyView(k, false)}
	case "/v2/DeleteKey":
		id := q.Get("id")
		if g.keys[id] == nil {
			return notFound
		}
		delete(g.keys, id)
		g.tombstones[id] = true
		for _, b := range g.buckets {
			delete(b.Perms, id)
		}
		return fgResp{}
	case "/v2/ListBuckets":
		out := []garage.BucketListItem{}
		for _, b := range g.buckets {
			out = append(out, garage.BucketListItem{ID: b.ID, GlobalAliases: sortedAliases(b), LocalAliases: []garage.BucketLocalAlias{}})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		return fgResp{body: out}
	case "/v2/GetBucketInfo":
		b := g.findBucket(q)
		if b == nil {
			return notFound
		}
		return fgResp{body: g.bucketView(b)}
	case "/v2/CreateBucket":
		var req garage.CreateBucketRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.GlobalAlias != "" {
			for _, b := range g.buckets {
				if b.Aliases[req.GlobalAlias] {
					return fgResp{status: http.StatusConflict, body: map[string]string{"message": "alias in use"}}
				}
			}
		}
		b := &fgBucket{ID: g.newID(), Aliases: map[string]bool{}, Perms: map[string]garage.BucketKeyPerms{}}
		if req.GlobalAlias != "" {
			b.Aliases[req.GlobalAlias] = true
		}
		g.buckets[b.ID] = b
		return fgResp{body: g.bucketView(b)}
	case "/v2/UpdateBucket":
		b := g.buckets[q.Get("id")]
		if b == nil {
			return notFound
		}
		var body garage.UpdateBucketRequestBody
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.WebsiteAccess != nil {
			b.Website = body.WebsiteAccess
		}
		if body.Quotas != nil {
			b.Quotas = body.Quotas
		}
		return fgResp{body: g.bucketView(b)}
	case "/v2/DeleteBucket":
		id := q.Get("id")
		if g.buckets[id] == nil {
			return notFound
		}
		delete(g.buckets, id)
		return fgResp{}
	case "/v2/AddBucketAlias":
		var req garage.AddBucketAliasRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		b := g.buckets[req.BucketID]
		if b == nil {
			return notFound
		}
		if req.GlobalAlias != "" {
			for _, o := range g.buckets {
				if o.ID != b.ID && o.Aliases[req.GlobalAlias] {
					return fgResp{status: http.StatusConflict, body: map[string]string{"message": "alias in use"}}
				}
			}
			b.Aliases[req.GlobalAlias] = true
		}
		return fgResp{body: g.bucketView(b)}
	case "/v2/RemoveBucketAlias":
		var req garage.RemoveBucketAliasRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		b := g.buckets[req.BucketID]
		if b == nil {
			return notFound
		}
		if req.GlobalAlias != "" {
			if !b.Aliases[req.GlobalAlias] {
				return fgResp{status: http.StatusBadRequest, body: map[string]string{"message": "alias not on bucket"}}
			}
			delete(b.Aliases, req.GlobalAlias)
		}
		return fgResp{body: g.bucketView(b)}
	case "/v2/AllowBucketKey", "/v2/DenyBucketKey":
		var req garage.AllowBucketKeyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		b := g.buckets[req.BucketID]
		if b == nil || g.keys[req.AccessKeyID] == nil {
			return notFound
		}
		p := b.Perms[req.AccessKeyID]
		allow := r.URL.Path == "/v2/AllowBucketKey"
		if req.Permissions.Read {
			p.Read = allow
		}
		if req.Permissions.Write {
			p.Write = allow
		}
		if req.Permissions.Owner {
			p.Owner = allow
		}
		b.Perms[req.AccessKeyID] = p
		return fgResp{body: g.bucketView(b)}
	}
	if g.extra != nil {
		if status, body, handled := g.extra(r); handled {
			return fgResp{status: status, body: body}
		}
	}
	return fgResp{status: http.StatusNotFound, body: map[string]string{"message": "unhandled " + r.URL.Path}}
}

// snapshot is a canonical text form of the Garage state, with IDs that Garage
// generates (random) normalised so runs can be compared.
func (g *fakeGarage) snapshot() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	lines := make([]string, 0, len(g.keys)+len(g.buckets))
	keyAlias := map[string]string{}
	for id, k := range g.keys {
		keyAlias[id] = "key(" + k.Name + ")"
	}
	for id, k := range g.keys {
		lines = append(lines, fmt.Sprintf("key %s name=%s createBucket=%v", keyOrID(id), k.Name, k.CreateBucket))
	}
	for _, b := range g.buckets {
		var perms []string
		for kid, p := range b.Perms {
			perms = append(perms, fmt.Sprintf("%s:%v", keyAlias[kid], p))
		}
		sort.Strings(perms)
		web := "-"
		if b.Website != nil {
			web = fmt.Sprintf("%v/%s", b.Website.Enabled, b.Website.IndexDocument)
		}
		lines = append(lines, fmt.Sprintf("bucket aliases=%v perms=%v website=%s", sortedAliases(b), perms, web))
	}
	sort.Strings(lines)
	if g.extraSnapshot != nil {
		lines = append(lines, g.extraSnapshot())
	}
	return strings.Join(lines, "\n")
}

// keyOrID keeps deterministic key IDs visible and hides random ones.
func keyOrID(id string) string {
	if strings.HasPrefix(id, "GK") {
		return "GK*"
	}
	return id
}

// ---------------------------------------------------------------------------
// Kubernetes write fault interceptor
// ---------------------------------------------------------------------------

type kubeFaultKind int

const (
	kubeFaultError    kubeFaultKind = iota // generic 500
	kubeFaultConflict                      // 409 Conflict
)

type kubeFaults struct {
	mu     sync.Mutex
	writes int
	failAt int // 1-based; 0 disables
	kind   kubeFaultKind
	hit    bool
	trace  []string
	// objWrites counts create/update/patch/delete (everything except status
	// subresource writes) to detect reconcile loops that never go quiet.
	objWrites int
}

func (f *kubeFaults) maybeFail(op string, obj client.Object) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	if !strings.HasPrefix(op, "status") {
		f.objWrites++
	}
	name := ""
	if obj != nil {
		name = fmt.Sprintf("%T/%s", obj, obj.GetName())
	}
	f.trace = append(f.trace, fmt.Sprintf("%d:%s:%s", f.writes, op, name))
	if f.failAt != 0 && f.writes == f.failAt {
		f.hit = true
		gr := schema.GroupResource{Group: "garage.rajsingh.info", Resource: "injected"}
		if f.kind == kubeFaultConflict {
			return apierrors.NewConflict(gr, name, fmt.Errorf("injected conflict"))
		}
		return apierrors.NewInternalError(fmt.Errorf("injected write failure"))
	}
	return nil
}

func (f *kubeFaults) wrap(base client.WithWatch) client.WithWatch {
	return interceptor.NewClient(base, interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if err := f.maybeFail("create", obj); err != nil {
				return err
			}
			return c.Create(ctx, obj, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if err := f.maybeFail("update", obj); err != nil {
				return err
			}
			return c.Update(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if err := f.maybeFail("patch", obj); err != nil {
				return err
			}
			return c.Patch(ctx, obj, patch, opts...)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if err := f.maybeFail("delete", obj); err != nil {
				return err
			}
			return c.Delete(ctx, obj, opts...)
		},
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if err := f.maybeFail("status-update", obj); err != nil {
				return err
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
		SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			if err := f.maybeFail("status-patch", obj); err != nil {
				return err
			}
			return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	})
}

// ---------------------------------------------------------------------------
// Sweep driver
// ---------------------------------------------------------------------------

// faultScenario is one reconcile flow under test. build must return a fresh,
// isolated environment each call.
type faultScenario struct {
	name string
	// build creates the fake Garage, the (fault-wrapped) client and a step
	// function that runs one reconcile pass. observe renders the K8s-side end
	// state canonically; done reports whether the flow has finished.
	build func(t *testing.T, kf *kubeFaults, gf *fakeGarage, scheme *runtime.Scheme) *faultEnv
	// maxRetries bounds fault-free reconciles after the fault.
	maxRetries int
}

type faultEnv struct {
	step    func(ctx context.Context) error
	observe func(ctx context.Context) string
	done    func(ctx context.Context) bool
}

type runResult struct {
	steadyObjWrites int
	steadyMutations int
	kubeWrites      int
	garageCalls     int
	garageSnap      string
	kubeSnap        string
	converged       bool
	lastErr         error
	kubeFaultHit    bool
	garageFaultHit  bool
	kubeTrace       []string
	garageTrace     []string
}

func runFaultFlow(t *testing.T, sc faultScenario, kubeFailAt int, kubeKind kubeFaultKind, garageFail *garageFault, second ...func(*kubeFaults, *fakeGarage)) runResult {
	t.Helper()
	ctx := context.Background()
	kf := &kubeFaults{failAt: kubeFailAt, kind: kubeKind}
	gf := newFakeGarage(t)
	gf.fault = garageFail
	env := sc.build(t, kf, gf, testSchemeForFault(t))

	// Pass 1 may hit the fault.
	_ = env.step(ctx)
	// Optionally arm a second fault that fires during the retry pass, i.e. the
	// recovery from the first partial failure is itself interrupted.
	if len(second) > 0 {
		kf.mu.Lock()
		kf.failAt = 0
		kf.mu.Unlock()
		gf.mu.Lock()
		gf.fault = nil
		gf.mu.Unlock()
		second[0](kf, gf)
		_ = env.step(ctx)
	}
	// Disable faults, then retry to convergence.
	kf.mu.Lock()
	kf.failAt = 0
	kf.mu.Unlock()
	gf.mu.Lock()
	gf.fault = nil
	gf.mu.Unlock()

	maxRetries := sc.maxRetries
	if maxRetries == 0 {
		maxRetries = 12
	}
	var lastErr error
	converged := false
	for i := 0; i < maxRetries; i++ {
		lastErr = env.step(ctx)
		if env.done(ctx) {
			converged = true
			break
		}
	}
	// Extra settle passes: a converged flow must be a fixed point.
	for i := 0; i < 2; i++ {
		_ = env.step(ctx)
	}
	// Steady state: further passes must not mutate Garage or rewrite objects.
	kf.mu.Lock()
	objBefore := kf.objWrites
	kf.mu.Unlock()
	gf.mu.Lock()
	mutBefore := gf.mutations
	gf.mu.Unlock()
	for i := 0; i < 3; i++ {
		_ = env.step(ctx)
	}
	kf.mu.Lock()
	steadyObj := kf.objWrites - objBefore
	kf.mu.Unlock()
	gf.mu.Lock()
	steadyMut := gf.mutations - mutBefore
	gf.mu.Unlock()
	return runResult{
		steadyObjWrites: steadyObj,
		steadyMutations: steadyMut,
		kubeWrites:      kf.writes,
		garageCalls:     gf.calls,
		garageSnap:      gf.snapshot(),
		kubeSnap:        env.observe(ctx),
		converged:       converged,
		lastErr:         lastErr,
		kubeFaultHit:    kf.hit,
		garageFaultHit:  gf.faultHit,
		kubeTrace:       kf.trace,
		garageTrace:     gf.trace,
	}
}

// sweepFaults runs the scenario fault-free, then once for every K8s write
// position (error and conflict) and every Admin API call position (fail before
// and after commit). Every faulted run must converge to the baseline end state.
func sweepFaults(t *testing.T, sc faultScenario) {
	t.Helper()
	// Reconciles publish into process-global Prometheus vectors; leave them as
	// found so metric-lifecycle tests elsewhere in the package stay isolated.
	t.Cleanup(resetBucketQuotaMetricsForFaultTests)
	base := runFaultFlow(t, sc, 0, kubeFaultError, nil)
	if !base.converged {
		t.Fatalf("%s: baseline did not converge (last error: %v)\nkube trace: %v\ngarage trace: %v", sc.name, base.lastErr, base.kubeTrace, base.garageTrace)
	}
	t.Logf("%s: baseline kubeWrites=%d garageCalls=%d", sc.name, base.kubeWrites, base.garageCalls)

	if base.steadyObjWrites != 0 || base.steadyMutations != 0 {
		t.Errorf("%s: converged state is not quiet: %d object writes and %d Garage mutations over 3 further passes\nkube trace: %v\ngarage trace: %v",
			sc.name, base.steadyObjWrites, base.steadyMutations, base.kubeTrace, base.garageTrace)
	}
	check := func(label string, got runResult) {
		if got.steadyObjWrites != 0 || got.steadyMutations != 0 {
			t.Errorf("%s [%s]: converged state is not quiet: %d object writes, %d Garage mutations", sc.name, label, got.steadyObjWrites, got.steadyMutations)
		}
		if !got.converged {
			t.Errorf("%s [%s]: did not converge after fault (last error: %v)\nkube trace: %v\ngarage trace: %v", sc.name, label, got.lastErr, got.kubeTrace, got.garageTrace)
			return
		}
		if got.garageSnap != base.garageSnap {
			t.Errorf("%s [%s]: Garage end state diverged from uninterrupted run\n--- baseline\n%s\n--- faulted\n%s\ngarage trace: %v", sc.name, label, base.garageSnap, got.garageSnap, got.garageTrace)
		}
		if got.kubeSnap != base.kubeSnap {
			t.Errorf("%s [%s]: Kubernetes end state diverged from uninterrupted run\n--- baseline\n%s\n--- faulted\n%s", sc.name, label, base.kubeSnap, got.kubeSnap)
		}
	}

	for i := 1; i <= base.kubeWrites; i++ {
		for _, kind := range []kubeFaultKind{kubeFaultError, kubeFaultConflict} {
			label := fmt.Sprintf("kube write #%d kind=%d", i, kind)
			res := runFaultFlow(t, sc, i, kind, nil)
			if !res.kubeFaultHit {
				continue // fault position no longer reached after earlier divergence
			}
			check(label, res)
		}
	}
	for i := 1; i <= base.garageCalls; i++ {
		for _, after := range []bool{false, true} {
			label := fmt.Sprintf("garage call #%d afterCommit=%v", i, after)
			res := runFaultFlow(t, sc, 0, kubeFaultError, &garageFault{At: i, AfterCommit: after})
			if !res.garageFaultHit {
				continue
			}
			check(label, res)
		}
	}
}

// sweepDoubleFaults interrupts the recovery of a first partial failure with a
// second fault: a lost Garage response first and a failed Kubernetes write while
// retrying, and the reverse. Every combination must still converge to the
// uninterrupted end state.
func sweepDoubleFaults(t *testing.T, sc faultScenario) {
	t.Helper()
	t.Cleanup(resetBucketQuotaMetricsForFaultTests)
	base := runFaultFlow(t, sc, 0, kubeFaultError, nil)
	if !base.converged {
		t.Fatalf("%s: baseline did not converge: %v", sc.name, base.lastErr)
	}
	secondKube := func(rel int) func(*kubeFaults, *fakeGarage) {
		return func(kf *kubeFaults, _ *fakeGarage) {
			kf.mu.Lock()
			kf.failAt, kf.kind, kf.hit = kf.writes+rel, kubeFaultError, false
			kf.mu.Unlock()
		}
	}
	secondGarage := func(rel int, after bool) func(*kubeFaults, *fakeGarage) {
		return func(_ *kubeFaults, gf *fakeGarage) {
			gf.mu.Lock()
			gf.fault, gf.faultHit = &garageFault{At: gf.calls + rel, AfterCommit: after}, false
			gf.mu.Unlock()
		}
	}
	check := func(label string, got runResult) {
		switch {
		case !got.converged:
			t.Errorf("%s [%s]: did not converge: %v", sc.name, label, got.lastErr)
		case got.garageSnap != base.garageSnap:
			t.Errorf("%s [%s]: Garage end state diverged\n--- baseline\n%s\n--- faulted\n%s", sc.name, label, base.garageSnap, got.garageSnap)
		case got.kubeSnap != base.kubeSnap:
			t.Errorf("%s [%s]: Kubernetes end state diverged\n--- baseline\n%s\n--- faulted\n%s", sc.name, label, base.kubeSnap, got.kubeSnap)
		case got.steadyObjWrites != 0 || got.steadyMutations != 0:
			t.Errorf("%s [%s]: converged state is not quiet", sc.name, label)
		}
	}
	for i := 1; i <= base.garageCalls; i++ {
		for j := 1; j <= base.kubeWrites; j++ {
			res := runFaultFlow(t, sc, 0, kubeFaultError, &garageFault{At: i, AfterCommit: true}, secondKube(j))
			if res.garageFaultHit && res.kubeFaultHit {
				check(fmt.Sprintf("garage #%d lost response, then kube retry write #%d fails", i, j), res)
			}
		}
	}
	for i := 1; i <= base.kubeWrites; i++ {
		for j := 1; j <= base.garageCalls; j++ {
			for _, after := range []bool{false, true} {
				res := runFaultFlow(t, sc, i, kubeFaultError, nil, secondGarage(j, after))
				if res.kubeFaultHit && res.garageFaultHit {
					check(fmt.Sprintf("kube write #%d fails, then retry garage call #%d fails (afterCommit=%v)", i, j, after), res)
				}
			}
		}
	}
}

func resetBucketQuotaMetricsForFaultTests() {
	for _, v := range []*prometheus.GaugeVec{
		bucketQuotaSizeBytes, bucketQuotaSizeLimitBytes, bucketQuotaSizeUtilizationRatio,
		bucketQuotaObjectCount, bucketQuotaObjectLimit, bucketQuotaObjectUtilizationRatio,
	} {
		v.Reset()
	}
}
