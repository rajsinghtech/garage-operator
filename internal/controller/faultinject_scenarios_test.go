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
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

const (
	fiNS       = "tenant"
	fiCluster  = "gc"
	fiRPCHex   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	fiTokenSec = "gc-admin"
)

func testSchemeForFault(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, appsv1.AddToScheme,
		garagev1beta1.AddToScheme, garagev1beta2.AddToScheme,
	} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// faultBaseObjects returns the management-handle GarageCluster and its secrets.
func faultBaseObjects(endpoint string) []client.Object {
	return []client.Object{
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: fiTokenSec, Namespace: fiNS},
			Data:       map[string][]byte{DefaultAdminTokenKey: []byte("prefix.secret")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: fiCluster + "-" + RPCSecretKey, Namespace: fiNS},
			Data:       map[string][]byte{RPCSecretKey: []byte(fiRPCHex)},
		},
		&garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: fiCluster, Namespace: fiNS, UID: "cluster-uid"},
			Spec: garagev1beta2.GarageClusterSpec{
				ConnectTo: &garagev1beta2.ConnectToConfig{
					AdminAPIEndpoint: endpoint,
					AdminTokenSecretRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: fiTokenSec},
						Key:                  DefaultAdminTokenKey,
					},
				},
			},
			Status: garagev1beta2.GarageClusterStatus{Phase: PhaseRunning},
		},
	}
}

func newFaultKube(t *testing.T, kf *kubeFaults, scheme *runtime.Scheme, objs ...client.Object) client.Client {
	t.Helper()
	base := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&garagev1beta1.GarageKey{}, &garagev1beta1.GarageAdminToken{}, &garagev1beta1.GarageBucket{}, &garagev1beta1.GarageNode{}, &garagev1beta2.GarageCluster{}).
		Build()
	return kf.wrap(base)
}

// dumpStrings renders map keys deterministically.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// -- GarageKey -------------------------------------------------------------

// scenarioHooks extends a scenario: after converges the initial object fault-free,
// then applies the spec mutation under test; final decides completion afterwards.
type scenarioHooks struct {
	// objects adds extra pre-existing API objects.
	objects func() []client.Object
	after   func(ctx context.Context, kube client.Client, gf *fakeGarage) error
	final   func(ctx context.Context, kube client.Client, gf *fakeGarage) bool
}

func keyScenario(name string, mutate func(k *garagev1beta1.GarageKey), extra func(gf *fakeGarage) []client.Object, deleting bool, hooks ...scenarioHooks) faultScenario {
	return faultScenario{
		name: name,
		build: func(t *testing.T, kf *kubeFaults, gf *fakeGarage, scheme *runtime.Scheme) *faultEnv {
			key := &garagev1beta1.GarageKey{
				ObjectMeta: metav1.ObjectMeta{Name: "k1", Namespace: fiNS, UID: "key-uid"},
				Spec:       garagev1beta1.GarageKeySpec{ClusterRef: garagev1beta1.ClusterReference{Name: fiCluster}},
			}
			key.Spec.SecretTemplate = &garagev1beta1.SecretTemplate{IncludeEndpoint: ptr.To(false)}
			if mutate != nil {
				mutate(key)
			}
			objs := faultBaseObjects(gf.url())
			if extra != nil {
				objs = append(objs, extra(gf)...)
			}
			if deleting {
				now := metav1.NewTime(time.Now())
				key.DeletionTimestamp = &now
				key.Finalizers = []string{garageKeyFinalizer}
			}
			objs = append(objs, key)
			if len(hooks) > 0 && hooks[0].objects != nil {
				objs = append(objs, hooks[0].objects()...)
			}
			kube := newFaultKube(t, kf, scheme, objs...)
			r := &GarageKeyReconciler{Client: kube, Scheme: scheme}
			nn := types.NamespacedName{Name: "k1", Namespace: fiNS}
			step := func(ctx context.Context) error {
				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
				return err
			}
			ready := func(ctx context.Context) bool {
				got := &garagev1beta1.GarageKey{}
				err := kube.Get(ctx, nn, got)
				if deleting {
					return apierrors.IsNotFound(err)
				}
				if apierrors.IsNotFound(err) {
					return len(hooks) > 0 && hooks[0].after != nil // after a post-converge delete the object is gone
				}
				return err == nil && got.Status.Phase == PhaseReady
			}
			done := ready
			if len(hooks) > 0 && hooks[0].after != nil {
				h := hooks[0]
				withoutFaults(kf, gf, func() {
					ctx := context.Background()
					for i := 0; i < 12 && !ready(ctx); i++ {
						_ = step(ctx)
					}
					if !ready(ctx) {
						t.Fatalf("%s: initial object never became ready", name)
					}
					for i := 0; i < 2; i++ {
						_ = step(ctx)
					}
					if err := h.after(ctx, kube, gf); err != nil {
						t.Fatalf("%s: applying mutation: %v", name, err)
					}
				})
				done = func(ctx context.Context) bool { return ready(ctx) && h.final(ctx, kube, gf) }
			}
			return &faultEnv{
				step: step,
				done: done,
				observe: func(ctx context.Context) string {
					got := &garagev1beta1.GarageKey{}
					if err := kube.Get(ctx, nn, got); err != nil {
						return "key: " + err.Error()
					}
					var b strings.Builder
					// The ID itself may legitimately differ between runs (random replacement
					// nonce after a tombstone); the Garage snapshot checks the remote side.
					fmt.Fprintf(&b, "phase=%s finalizers=%v accessKeyIdSet=%v\n", got.Status.Phase, got.Finalizers, got.Status.AccessKeyID != "")
					for _, c := range got.Status.Conditions {
						if c.Status != metav1.ConditionTrue {
							fmt.Fprintf(&b, "condition %s=%s %s: %s\n", c.Type, c.Status, c.Reason, c.Message)
						}
					}
					secrets := &corev1.SecretList{}
					_ = kube.List(ctx, secrets, client.InNamespace(fiNS))
					names := map[string][]string{}
					for _, s := range secrets.Items {
						if s.Name == fiTokenSec || s.Name == fiCluster+"-"+RPCSecretKey {
							continue
						}
						names[s.Name] = sortedKeys(s.Data)
					}
					for _, n := range sortedKeys(names) {
						fmt.Fprintf(&b, "secret %s keys=%v\n", n, names[n])
					}
					return b.String()
				},
			}
		},
	}
}

func TestFaultSweep_GarageKeyCreate(t *testing.T) {
	sweepFaults(t, keyScenario("key-create", nil, nil, false))
}

func TestFaultSweep_GarageKeyCreateWithSpecName(t *testing.T) {
	sweepFaults(t, keyScenario("key-create-spec-name", func(k *garagev1beta1.GarageKey) {
		k.Spec.Name = "display-name"
	}, nil, false))
}

func TestFaultSweep_GarageKeyDelete(t *testing.T) {
	// The Garage key was created by an earlier reconcile; deletion must remove
	// it and release the finalizer, whatever fails on the way.
	sc := keyScenario("key-delete", func(k *garagev1beta1.GarageKey) {
		id, _ := deriveKeyMaterial(mustHex(fiRPCHex), fiNS, "k1")
		k.Status.AccessKeyID = id
		k.Status.KeyID = id
	}, nil, true)
	inner := sc.build
	sc.build = func(t *testing.T, kf *kubeFaults, gf *fakeGarage, scheme *runtime.Scheme) *faultEnv {
		id, secret := deriveKeyMaterial(mustHex(fiRPCHex), fiNS, "k1")
		gf.keys[id] = &fgKey{ID: id, Secret: secret, Name: "k1"}
		return inner(t, kf, gf, scheme)
	}
	sweepFaults(t, sc)
}

func mustHex(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := range out {
		var v byte
		_, _ = fmt.Sscanf(s[2*i:2*i+2], "%02x", &v)
		out[i] = v
	}
	return out
}

// -- GarageBucket ----------------------------------------------------------

func bucketScenario(name string, mutate func(b *garagev1beta1.GarageBucket), seed func(gf *fakeGarage), deleting bool, hooks ...scenarioHooks) faultScenario {
	return faultScenario{
		name: name,
		build: func(t *testing.T, kf *kubeFaults, gf *fakeGarage, scheme *runtime.Scheme) *faultEnv {
			bucket := &garagev1beta1.GarageBucket{
				ObjectMeta: metav1.ObjectMeta{Name: "bucket-one", Namespace: fiNS, UID: "bucket-uid"},
				Spec:       garagev1beta1.GarageBucketSpec{ClusterRef: garagev1beta1.ClusterReference{Name: fiCluster}},
			}
			if mutate != nil {
				mutate(bucket)
			}
			if seed != nil {
				seed(gf)
			}
			if deleting {
				now := metav1.NewTime(time.Now())
				bucket.DeletionTimestamp = &now
				bucket.Finalizers = []string{garageBucketFinalizer}
			}
			objs := append(faultBaseObjects(gf.url()), bucket)
			if len(hooks) > 0 && hooks[0].objects != nil {
				objs = append(objs, hooks[0].objects()...)
			}
			kube := newFaultKube(t, kf, scheme, objs...)
			r := &GarageBucketReconciler{Client: kube, Scheme: scheme}
			nn := types.NamespacedName{Name: "bucket-one", Namespace: fiNS}
			step := func(ctx context.Context) error {
				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
				return err
			}
			ready := func(ctx context.Context) bool {
				got := &garagev1beta1.GarageBucket{}
				err := kube.Get(ctx, nn, got)
				if deleting {
					return apierrors.IsNotFound(err)
				}
				if apierrors.IsNotFound(err) {
					return len(hooks) > 0 && hooks[0].after != nil // after a post-converge delete the object is gone
				}
				return err == nil && got.Status.Phase == PhaseReady
			}
			done := ready
			if len(hooks) > 0 && hooks[0].after != nil {
				h := hooks[0]
				withoutFaults(kf, gf, func() {
					ctx := context.Background()
					for i := 0; i < 12 && !ready(ctx); i++ {
						_ = step(ctx)
					}
					if !ready(ctx) {
						t.Fatalf("%s: initial object never became ready", name)
					}
					for i := 0; i < 2; i++ {
						_ = step(ctx)
					}
					if err := h.after(ctx, kube, gf); err != nil {
						t.Fatalf("%s: applying mutation: %v", name, err)
					}
				})
				done = func(ctx context.Context) bool { return ready(ctx) && h.final(ctx, kube, gf) }
			}
			return &faultEnv{
				step: step,
				done: done,
				observe: func(ctx context.Context) string {
					got := &garagev1beta1.GarageBucket{}
					if err := kube.Get(ctx, nn, got); err != nil {
						return "bucket: " + err.Error()
					}
					ann := []string{}
					for k := range got.Annotations {
						ann = append(ann, k)
					}
					sort.Strings(ann)
					out := fmt.Sprintf("phase=%s finalizers=%v annotations=%v managedAlias=%q pendingAlias=%q hasID=%v",
						got.Status.Phase, got.Finalizers, ann, got.Status.ManagedGlobalAlias, got.Status.PendingGlobalAlias, got.Status.BucketID != "")
					for _, c := range got.Status.Conditions {
						if c.Status != metav1.ConditionTrue {
							out += fmt.Sprintf("\ncondition %s=%s %s: %s", c.Type, c.Status, c.Reason, c.Message)
						}
					}
					return out
				},
			}
		},
	}
}

func TestFaultSweep_GarageBucketCreate(t *testing.T) {
	sweepFaults(t, bucketScenario("bucket-create", nil, nil, false))
}

func TestFaultSweep_GarageBucketCreateGlobalAliasWebsiteQuota(t *testing.T) {
	sweepFaults(t, bucketScenario("bucket-create-full", func(b *garagev1beta1.GarageBucket) {
		b.Spec.GlobalAlias = "public-assets"
		b.Spec.Website = &garagev1beta1.WebsiteConfig{Enabled: ptr.To(true), IndexDocument: "index.html"}
		size := resource.MustParse("1Gi")
		b.Spec.Quotas = &garagev1beta1.BucketQuotas{MaxSize: &size}
	}, nil, false))
}

func TestFaultSweep_GarageBucketDelete(t *testing.T) {
	sc := bucketScenario("bucket-delete", func(b *garagev1beta1.GarageBucket) {
		b.Status.BucketID = fmt.Sprintf("%064x", 1)
	}, func(gf *fakeGarage) {
		id := fmt.Sprintf("%064x", 1)
		gf.buckets[id] = &fgBucket{ID: id, Aliases: map[string]bool{"bucket-one": true}, Perms: map[string]garage.BucketKeyPerms{}}
		gf.nextID = 1
	}, true)
	sweepFaults(t, sc)
}

// -- Auto-mode GarageNode hand-off / lifecycle --------------------------------

func autoModeClusterObj(policy string) *garagev1beta2.GarageCluster {
	return &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "auto", Namespace: fiNS, UID: "auto-uid"},
		Spec: garagev1beta2.GarageClusterSpec{
			LayoutPolicy: policy,
			Storage: &garagev1beta2.StorageSpec{
				Replicas: 3,
				Metadata: &garagev1beta2.VolumeConfig{Size: ptr.To(resource.MustParse("1Gi"))},
				Data:     &garagev1beta2.VolumeConfig{Size: ptr.To(resource.MustParse("10Gi"))},
			},
			Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
		},
	}
}

// withoutFaults runs seed with fault counting suspended, then resets counters.
func withoutFaults(kf *kubeFaults, gf *fakeGarage, seed func()) {
	kf.mu.Lock()
	saved := kf.failAt
	kf.failAt = 0
	kf.mu.Unlock()
	gf.mu.Lock()
	savedFault := gf.fault
	gf.fault = nil
	gf.mu.Unlock()
	seed()
	kf.mu.Lock()
	kf.failAt = saved
	kf.writes = 0
	kf.trace = nil
	kf.mu.Unlock()
	gf.mu.Lock()
	gf.fault = savedFault
	gf.calls = 0
	gf.mutations = 0
	gf.trace = nil
	gf.mu.Unlock()
}

func autoNodesObserve(kube client.Client) func(ctx context.Context) string {
	return func(ctx context.Context) string {
		list := &garagev1beta1.GarageNodeList{}
		_ = kube.List(ctx, list, client.InNamespace(fiNS))
		cluster := &garagev1beta2.GarageCluster{}
		_ = kube.Get(ctx, types.NamespacedName{Name: "auto", Namespace: fiNS}, cluster)
		lines := make([]string, 0, len(list.Items))
		for _, n := range list.Items {
			owned := metav1.IsControlledBy(&n, cluster)
			_, managed := n.Labels[labelAppManagedBy]
			lines = append(lines, fmt.Sprintf("node %s controlled=%v managedBy=%v deleting=%v", n.Name, owned, managed, !n.DeletionTimestamp.IsZero()))
		}
		sort.Strings(lines)
		return strings.Join(lines, "\n")
	}
}

func autoModeNodesScenario(name string, startPolicy, runPolicy string, seed bool, done func(nodes []garagev1beta1.GarageNode, c *garagev1beta2.GarageCluster) bool, run func(r *GarageClusterReconciler, ctx context.Context, c *garagev1beta2.GarageCluster) error) faultScenario {
	return faultScenario{
		name: name,
		build: func(t *testing.T, kf *kubeFaults, gf *fakeGarage, scheme *runtime.Scheme) *faultEnv {
			cluster := autoModeClusterObj(startPolicy)
			kube := newFaultKube(t, kf, scheme, cluster)
			r := &GarageClusterReconciler{Client: kube, Scheme: scheme}
			nn := types.NamespacedName{Name: "auto", Namespace: fiNS}
			if seed {
				withoutFaults(kf, gf, func() {
					c := &garagev1beta2.GarageCluster{}
					if err := kube.Get(context.Background(), nn, c); err != nil {
						t.Fatal(err)
					}
					if err := r.reconcileAutoModeStorageNodes(context.Background(), c); err != nil {
						t.Fatalf("seeding Auto-mode nodes: %v", err)
					}
					c.Spec.LayoutPolicy = runPolicy
					if err := kube.Update(context.Background(), c); err != nil {
						t.Fatal(err)
					}
				})
			}
			return &faultEnv{
				step: func(ctx context.Context) error {
					c := &garagev1beta2.GarageCluster{}
					if err := kube.Get(ctx, nn, c); err != nil {
						return err
					}
					return run(r, ctx, c)
				},
				done: func(ctx context.Context) bool {
					list := &garagev1beta1.GarageNodeList{}
					_ = kube.List(ctx, list, client.InNamespace(fiNS))
					c := &garagev1beta2.GarageCluster{}
					_ = kube.Get(ctx, nn, c)
					return done(list.Items, c)
				},
				observe: autoNodesObserve(kube),
			}
		},
	}
}

func TestFaultSweep_AutoModeStorageEject(t *testing.T) {
	// Auto -> Manual hand-off of three nodes (regression class for #466).
	sweepFaults(t, autoModeNodesScenario("automode-eject", LayoutPolicyAuto, LayoutPolicyManual, true,
		func(nodes []garagev1beta1.GarageNode, c *garagev1beta2.GarageCluster) bool {
			if len(nodes) != 3 {
				return false
			}
			for i := range nodes {
				if metav1.IsControlledBy(&nodes[i], c) {
					return false
				}
				if _, managed := nodes[i].Labels[labelAppManagedBy]; managed {
					return false
				}
			}
			return true
		},
		func(r *GarageClusterReconciler, ctx context.Context, c *garagev1beta2.GarageCluster) error {
			return r.ejectAutoModeStorageNodes(ctx, c)
		}))
}

// -- Post-converge spec mutations ------------------------------------------------

func updateObj[T client.Object](ctx context.Context, kube client.Client, obj T, nn types.NamespacedName, mutate func(T)) error {
	if err := kube.Get(ctx, nn, obj); err != nil {
		return err
	}
	mutate(obj)
	return kube.Update(ctx, obj)
}

func TestFaultSweep_GarageBucketRenameGlobalAlias(t *testing.T) {
	nn := types.NamespacedName{Name: "bucket-one", Namespace: fiNS}
	sweepFaults(t, bucketScenario("bucket-rename-alias", func(b *garagev1beta1.GarageBucket) {
		b.Spec.GlobalAlias = "alias-one"
	}, nil, false, scenarioHooks{
		after: func(ctx context.Context, kube client.Client, gf *fakeGarage) error {
			return updateObj(ctx, kube, &garagev1beta1.GarageBucket{}, nn, func(b *garagev1beta1.GarageBucket) { b.Spec.GlobalAlias = "alias-two" })
		},
		final: func(ctx context.Context, kube client.Client, gf *fakeGarage) bool {
			b := &garagev1beta1.GarageBucket{}
			if err := kube.Get(ctx, nn, b); err != nil {
				return false
			}
			gf.mu.Lock()
			defer gf.mu.Unlock()
			for _, gb := range gf.buckets {
				if gb.Aliases["alias-two"] && !gb.Aliases["alias-one"] {
					return b.Status.ManagedGlobalAlias == "alias-two" && b.Status.PendingGlobalAlias == ""
				}
			}
			return false
		},
	}))
}

func TestFaultSweep_GarageBucketDisableWebsiteAndQuota(t *testing.T) {
	nn := types.NamespacedName{Name: "bucket-one", Namespace: fiNS}
	sweepFaults(t, bucketScenario("bucket-disable-website", func(b *garagev1beta1.GarageBucket) {
		b.Spec.Website = &garagev1beta1.WebsiteConfig{Enabled: ptr.To(true), IndexDocument: "index.html"}
	}, nil, false, scenarioHooks{
		after: func(ctx context.Context, kube client.Client, gf *fakeGarage) error {
			return updateObj(ctx, kube, &garagev1beta1.GarageBucket{}, nn, func(b *garagev1beta1.GarageBucket) { b.Spec.Website = nil })
		},
		final: func(ctx context.Context, kube client.Client, gf *fakeGarage) bool {
			gf.mu.Lock()
			defer gf.mu.Unlock()
			for _, gb := range gf.buckets {
				return gb.Website == nil || !gb.Website.Enabled
			}
			return false
		},
	}))
}

func TestFaultSweep_GarageKeyRenameSecret(t *testing.T) {
	nn := types.NamespacedName{Name: "k1", Namespace: fiNS}
	sweepFaults(t, keyScenario("key-rename-secret", func(k *garagev1beta1.GarageKey) {
		k.Spec.SecretTemplate.Name = "sec-a"
	}, nil, false, scenarioHooks{
		after: func(ctx context.Context, kube client.Client, gf *fakeGarage) error {
			return updateObj(ctx, kube, &garagev1beta1.GarageKey{}, nn, func(k *garagev1beta1.GarageKey) { k.Spec.SecretTemplate.Name = "sec-b" })
		},
		final: func(ctx context.Context, kube client.Client, gf *fakeGarage) bool {
			k := &garagev1beta1.GarageKey{}
			if err := kube.Get(ctx, nn, k); err != nil {
				return false
			}
			return k.Status.SecretRef != nil && k.Status.SecretRef.Name == "sec-b" &&
				apierrors.IsNotFound(kube.Get(ctx, types.NamespacedName{Name: "sec-a", Namespace: fiNS}, &corev1.Secret{}))
		},
	}))
}

func TestFaultSweep_GarageKeyDeleteAfterReady(t *testing.T) {
	nn := types.NamespacedName{Name: "k1", Namespace: fiNS}
	sweepFaults(t, keyScenario("key-delete-after-ready", nil, nil, false, scenarioHooks{
		after: func(ctx context.Context, kube client.Client, gf *fakeGarage) error {
			k := &garagev1beta1.GarageKey{}
			if err := kube.Get(ctx, nn, k); err != nil {
				return err
			}
			return kube.Delete(ctx, k)
		},
		final: func(ctx context.Context, kube client.Client, gf *fakeGarage) bool { return true },
	}))
}

// -- GarageNode layout role add / remove (shared layout fake) ------------------

// faultProxy forwards to the shared layout fake and fails the Nth request, either
// before it reaches Garage or after it committed (response lost).
type faultProxy struct {
	mu      sync.Mutex
	target  string
	calls   int
	failAt  int
	after   bool
	hit     bool
	srv     *httptest.Server
	methods []string
}

func newFaultProxy(t *testing.T, target string) *faultProxy {
	p := &faultProxy{target: target}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.calls++
		n := p.calls
		p.methods = append(p.methods, r.URL.Path)
		fail := p.failAt != 0 && n == p.failAt
		after := p.after
		if fail {
			p.hit = true
		}
		p.mu.Unlock()
		if fail && !after {
			http.Error(w, "injected fault", http.StatusInternalServerError)
			return
		}
		body, _ := io.ReadAll(r.Body)
		req, _ := http.NewRequestWithContext(r.Context(), r.Method, p.target+r.URL.RequestURI(), bytes.NewReader(body))
		req.Header = r.Header.Clone()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		if fail && after {
			http.Error(w, "injected fault after commit", http.StatusInternalServerError)
			return
		}
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func layoutSnapshot(f *fakeGarageLayout) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := make([]string, 0, len(f.roles))
	for id, role := range f.roles {
		capStr := "gw"
		if role.Capacity != nil {
			capStr = fmt.Sprint(*role.Capacity)
		}
		ids = append(ids, fmt.Sprintf("%s/%s/%s/%v", id[:8], role.Zone, capStr, role.Tags))
	}
	sort.Strings(ids)
	return fmt.Sprintf("roles=%v staged=%d applies=%d draining=%d", ids, len(f.staged), len(f.applies), len(f.drainingNodeIDs))
}

// nodeLayoutSweep runs one GarageNode reconcileNode flow against the layout fake
// with a single injected Admin API or Kubernetes write fault at every position.
//
//nolint:unparam // every current scenario targets the same replacement identity
func nodeLayoutSweep(t *testing.T, name string, nodeFn func() *garagev1beta1.GarageNode, initial []garage.LayoutNodeRole, wantRole string, wantAbsent bool, finalize ...bool) {
	finalizing := len(finalize) > 0 && finalize[0]
	t.Helper()
	const (
		localUID = "local-cluster-uid"
	)
	type outcome struct {
		snap      string
		nodeSnap  string
		converged bool
		lastErr   error
		garage    int
		kubeW     int
		garageHit bool
		kubeHit   bool
	}
	run := func(kubeFail int, kubeKind kubeFaultKind, garageFail int, after bool) outcome {
		ctx := context.Background()
		fake := newFakeGarageLayout(initial...)
		srv := fake.server()
		defer srv.Close()
		proxy := newFaultProxy(t, srv.URL)
		gclient := garage.NewClient(proxy.srv.URL, "test-token")

		node := nodeFn()
		node.Namespace = fiNS
		node.UID = types.UID("node-uid")
		node.Spec.ClusterRef = garagev1beta1.ClusterReference{Name: fiCluster}
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: fiCluster, Namespace: fiNS, UID: types.UID(localUID), Generation: 1},
			Spec: garagev1beta2.GarageClusterSpec{
				Replication: &garagev1beta2.ReplicationConfig{Factor: 1, ConsistencyMode: consistencyModeConsistent},
			},
			Status: garagev1beta2.GarageClusterStatus{
				Conditions: []metav1.Condition{{
					Type: garagev1beta1.ConditionStorageRolloutReady, Status: metav1.ConditionTrue,
					Reason: garagev1beta1.ReasonStorageRolloutConverged, ObservedGeneration: 1,
				}},
				Health: &garagev1beta2.ClusterHealth{
					Status: healthStatusHealthy, Healthy: true, Available: true,
					StorageNodes: 3, StorageNodesOK: 3, Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256,
				},
			},
		}
		kf := &kubeFaults{failAt: kubeFail, kind: kubeKind}
		scheme := testSchemeForFault(t)
		kube := newFaultKube(t, kf, scheme, cluster, node)
		r := &GarageNodeReconciler{
			Client:          kube,
			LayoutMutations: NewLayoutMutationCoordinator(),
			managedNodeIDGetter: func(context.Context, *garagev1beta1.GarageNode, *garagev1beta2.GarageCluster) (string, error) {
				return node.Spec.NodeID, nil
			},
			clusterHealthGetter: func(context.Context, *garage.Client) (*garage.ClusterHealth, error) {
				return &garage.ClusterHealth{
					Status: healthStatusHealthy, StorageNodes: 3, StorageNodesUp: 3,
					Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256,
				}, nil
			},
		}
		proxy.mu.Lock()
		proxy.failAt, proxy.after = garageFail, after
		proxy.mu.Unlock()
		nn := types.NamespacedName{Name: node.Name, Namespace: node.Namespace}
		cn := types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}
		step := func() error {
			n := &garagev1beta1.GarageNode{}
			c := &garagev1beta2.GarageCluster{}
			if err := kube.Get(ctx, nn, n); err != nil {
				return err
			}
			if err := kube.Get(ctx, cn, c); err != nil {
				return err
			}
			if finalizing {
				return r.finalize(ctx, n, c, gclient)
			}
			return r.reconcileNode(ctx, n, c, gclient, c)
		}
		_ = step()
		kf.mu.Lock()
		kf.failAt = 0
		kf.mu.Unlock()
		proxy.mu.Lock()
		proxy.failAt = 0
		proxy.mu.Unlock()
		converged := false
		var lastErr error
		for i := 0; i < 8; i++ {
			lastErr = step()
			if lastErr == nil {
				converged = true
				break
			}
		}
		_ = step()
		has := fake.hasRole(wantRole)
		if wantAbsent {
			has = !has
		}
		n := &garagev1beta1.GarageNode{}
		_ = kube.Get(ctx, nn, n)
		return outcome{
			snap:      layoutSnapshot(fake),
			nodeSnap:  fmt.Sprintf("roleOK=%v nodeID=%q", has, n.Status.NodeID),
			converged: converged && has, lastErr: lastErr,
			garage: proxy.calls, kubeW: kf.writes, garageHit: proxy.hit, kubeHit: kf.hit,
		}
	}

	base := run(0, kubeFaultError, 0, false)
	if !base.converged {
		t.Fatalf("%s: baseline did not converge: %v (%s %s)", name, base.lastErr, base.snap, base.nodeSnap)
	}
	t.Logf("%s: baseline kubeWrites=%d garageCalls=%d state=%s", name, base.kubeW, base.garage, base.snap)
	check := func(label string, got outcome) {
		if !got.converged {
			t.Errorf("%s [%s]: did not converge: %v (%s %s)", name, label, got.lastErr, got.snap, got.nodeSnap)
			return
		}
		if got.snap != base.snap || got.nodeSnap != base.nodeSnap {
			t.Errorf("%s [%s]: end state diverged\n  baseline: %s %s\n  faulted:  %s %s", name, label, base.snap, base.nodeSnap, got.snap, got.nodeSnap)
		}
	}
	for i := 1; i <= base.kubeW; i++ {
		for _, kind := range []kubeFaultKind{kubeFaultError, kubeFaultConflict} {
			got := run(i, kind, 0, false)
			if got.kubeHit {
				check(fmt.Sprintf("kube write #%d kind=%d", i, kind), got)
			}
		}
	}
	for i := 1; i <= base.garage; i++ {
		for _, after := range []bool{false, true} {
			got := run(0, kubeFaultError, i, after)
			if got.garageHit {
				check(fmt.Sprintf("garage call #%d afterCommit=%v", i, after), got)
			}
		}
	}
}

func TestFaultSweep_GarageNodeAddStorageRole(t *testing.T) {
	const (
		liveID = "fa7874a6114eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		newID  = "73143814f0e608c7737dde755727a45ca9b81414d76da011767fae2b867752fa"
	)
	cp := uint64(700 << 30)
	live := garage.LayoutNodeRole{ID: liveID, Zone: testZone, Tags: []string{testTierStorageTag}, Capacity: &cp}
	nodeLayoutSweep(t, "node-add-storage-role", func() *garagev1beta1.GarageNode {
		return &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "new-storage", Generation: 1},
			Spec: garagev1beta1.GarageNodeSpec{
				NodeID: newID, Zone: testZone,
				Capacity: resource.NewQuantity(700<<30, resource.BinarySI),
				Tags:     []string{testTierStorageTag},
			},
		}
	}, []garage.LayoutNodeRole{live}, newID, false)
}

func TestFaultSweep_GarageNodeAddGatewayRole(t *testing.T) {
	const (
		liveID = "fa7874a6114eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		newID  = "73143814f0e608c7737dde755727a45ca9b81414d76da011767fae2b867752fa"
	)
	cp := uint64(700 << 30)
	live := garage.LayoutNodeRole{ID: liveID, Zone: testZone, Tags: []string{testTierStorageTag}, Capacity: &cp}
	nodeLayoutSweep(t, "node-add-gateway-role", func() *garagev1beta1.GarageNode {
		return &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "new-gateway", Generation: 1},
			Spec: garagev1beta1.GarageNodeSpec{
				NodeID: newID, Zone: testZone, Gateway: true, Tags: []string{testTierGatewayTag},
			},
		}
	}, []garage.LayoutNodeRole{live}, newID, false)
}

// -- Permissions, import, tombstones -----------------------------------------------

func seedBucketForKey(gf *fakeGarage) []client.Object {
	id := fmt.Sprintf("%064x", 1)
	gf.buckets[id] = &fgBucket{ID: id, Aliases: map[string]bool{"bucket-one": true}, Perms: map[string]garage.BucketKeyPerms{}}
	gf.nextID = 1
	return []client.Object{&garagev1beta1.GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket-one", Namespace: fiNS, UID: "bucket-uid"},
		Spec:       garagev1beta1.GarageBucketSpec{ClusterRef: garagev1beta1.ClusterReference{Name: fiCluster}},
		Status:     garagev1beta1.GarageBucketStatus{BucketID: id, Phase: PhaseReady},
	}}
}

func bucketPermsFor(gf *fakeGarage, keyIDPrefix string) (garage.BucketKeyPerms, bool) {
	gf.mu.Lock()
	defer gf.mu.Unlock()
	for _, b := range gf.buckets {
		for kid, p := range b.Perms {
			if strings.HasPrefix(kid, keyIDPrefix) {
				return p, true
			}
		}
	}
	return garage.BucketKeyPerms{}, false
}

func TestFaultSweep_GarageKeyBucketPermissionsChange(t *testing.T) {
	nn := types.NamespacedName{Name: "k1", Namespace: fiNS}
	sweepFaults(t, keyScenario("key-perms-downgrade", func(k *garagev1beta1.GarageKey) {
		k.Spec.BucketPermissions = []garagev1beta1.BucketPermission{{
			BucketRef: &garagev1beta1.BucketRef{Name: "bucket-one"}, Read: true, Write: true,
		}}
	}, seedBucketForKey, false, scenarioHooks{
		after: func(ctx context.Context, kube client.Client, gf *fakeGarage) error {
			return updateObj(ctx, kube, &garagev1beta1.GarageKey{}, nn, func(k *garagev1beta1.GarageKey) {
				k.Spec.BucketPermissions[0].Write = false
			})
		},
		final: func(ctx context.Context, kube client.Client, gf *fakeGarage) bool {
			p, ok := bucketPermsFor(gf, "GK")
			return ok && p.Read && !p.Write
		},
	}))
}

func TestFaultSweep_GarageKeyBucketPermissionsRemoved(t *testing.T) {
	nn := types.NamespacedName{Name: "k1", Namespace: fiNS}
	sweepFaults(t, keyScenario("key-perms-removed", func(k *garagev1beta1.GarageKey) {
		k.Spec.BucketPermissions = []garagev1beta1.BucketPermission{{
			BucketRef: &garagev1beta1.BucketRef{Name: "bucket-one"}, Read: true, Write: true,
		}}
	}, seedBucketForKey, false, scenarioHooks{
		after: func(ctx context.Context, kube client.Client, gf *fakeGarage) error {
			return updateObj(ctx, kube, &garagev1beta1.GarageKey{}, nn, func(k *garagev1beta1.GarageKey) {
				k.Spec.BucketPermissions = nil
			})
		},
		final: func(ctx context.Context, kube client.Client, gf *fakeGarage) bool {
			p, _ := bucketPermsFor(gf, "GK")
			return !p.Read && !p.Write && !p.Owner
		},
	}))
}

func TestFaultSweep_GarageKeyBucketPermissionsCreate(t *testing.T) {
	sweepFaults(t, keyScenario("key-perms-create", func(k *garagev1beta1.GarageKey) {
		k.Spec.BucketPermissions = []garagev1beta1.BucketPermission{{
			BucketRef: &garagev1beta1.BucketRef{Name: "bucket-one"}, Read: true, Write: true,
		}}
	}, seedBucketForKey, false))
}

func TestFaultSweep_GarageKeyDeleteWithPermissions(t *testing.T) {
	nn := types.NamespacedName{Name: "k1", Namespace: fiNS}
	sweepFaults(t, keyScenario("key-delete-with-perms", func(k *garagev1beta1.GarageKey) {
		k.Spec.BucketPermissions = []garagev1beta1.BucketPermission{{
			BucketRef: &garagev1beta1.BucketRef{Name: "bucket-one"}, Read: true,
		}}
	}, seedBucketForKey, false, scenarioHooks{
		after: func(ctx context.Context, kube client.Client, gf *fakeGarage) error {
			k := &garagev1beta1.GarageKey{}
			if err := kube.Get(ctx, nn, k); err != nil {
				return err
			}
			return kube.Delete(ctx, k)
		},
		final: func(ctx context.Context, kube client.Client, gf *fakeGarage) bool { return true },
	}))
}

func TestFaultSweep_GarageKeyImportInline(t *testing.T) {
	sweepFaults(t, keyScenario("key-import-inline", func(k *garagev1beta1.GarageKey) {
		k.Spec.ImportKey = &garagev1beta1.ImportKeyConfig{
			AccessKeyID:     "GK0123456789abcdef01234567",
			SecretAccessKey: strings.Repeat("a1", 32),
		}
	}, nil, false))
}

func TestFaultSweep_GarageKeyImportFromSecret(t *testing.T) {
	sweepFaults(t, keyScenario("key-import-secretref", func(k *garagev1beta1.GarageKey) {
		k.Spec.ImportKey = &garagev1beta1.ImportKeyConfig{
			SecretRef: &corev1.SecretReference{Name: "import-src", Namespace: fiNS},
		}
	}, func(gf *fakeGarage) []client.Object {
		return []client.Object{&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "import-src", Namespace: fiNS},
			Data: map[string][]byte{
				"access-key-id":     []byte("GK0123456789abcdef01234567"),
				"secret-access-key": []byte(strings.Repeat("a1", 32)),
			},
		}}
	}, false))
}

func TestFaultSweep_GarageKeyTombstonedDeterministicID(t *testing.T) {
	// A previous incarnation's key ID is tombstoned in Garage, forcing the
	// replacement-identity path that persists a nonce annotation between steps.
	id, _ := deriveKeyMaterial(mustHex(fiRPCHex), fiNS, "k1")
	sweepFaults(t, keyScenario("key-tombstoned", nil, func(gf *fakeGarage) []client.Object {
		gf.tombstones[id] = true
		return nil
	}, false))
}

func seedKeyForBucket(gf *fakeGarage) {
	id := "GK00000000000000000000aa"
	gf.keys[id] = &fgKey{ID: id, Secret: strings.Repeat("b2", 32), Name: "consumer"}
}

func keyCRForBucket() *garagev1beta1.GarageKey {
	return &garagev1beta1.GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "consumer", Namespace: fiNS, UID: "consumer-uid"},
		Spec:       garagev1beta1.GarageKeySpec{ClusterRef: garagev1beta1.ClusterReference{Name: fiCluster}},
		Status:     garagev1beta1.GarageKeyStatus{AccessKeyID: "GK00000000000000000000aa", Phase: PhaseReady},
	}
}

func TestFaultSweep_GarageBucketKeyPermissions(t *testing.T) {
	nn := types.NamespacedName{Name: "bucket-one", Namespace: fiNS}
	var gfRef *fakeGarage
	sc := bucketScenario("bucket-key-perms", func(b *garagev1beta1.GarageBucket) {
		b.Spec.KeyPermissions = []garagev1beta1.KeyPermission{{
			KeyRef: garagev1beta1.KeyRef{Name: "consumer"}, Read: true, Write: true,
		}}
	}, func(gf *fakeGarage) {
		gfRef = gf
		seedKeyForBucket(gf)
	}, false, scenarioHooks{
		objects: func() []client.Object { return []client.Object{keyCRForBucket()} },
		after: func(ctx context.Context, kube client.Client, gf *fakeGarage) error {
			return updateObj(ctx, kube, &garagev1beta1.GarageBucket{}, nn, func(b *garagev1beta1.GarageBucket) {
				b.Spec.KeyPermissions = nil
			})
		},
		final: func(ctx context.Context, kube client.Client, gf *fakeGarage) bool {
			p, _ := bucketPermsFor(gf, "GK")
			return !p.Read && !p.Write
		},
	})
	_ = gfRef
	sweepFaults(t, sc)
}

func TestFaultSweep_GarageBucketKeyPermissionsCreate(t *testing.T) {
	sc := bucketScenario("bucket-key-perms-create", func(b *garagev1beta1.GarageBucket) {
		b.Spec.KeyPermissions = []garagev1beta1.KeyPermission{{
			KeyRef: garagev1beta1.KeyRef{Name: "consumer"}, Read: true,
		}}
	}, func(gf *fakeGarage) { seedKeyForBucket(gf) }, false, scenarioHooks{
		objects: func() []client.Object { return []client.Object{keyCRForBucket()} },
	})
	sweepFaults(t, sc)
}

// -- GarageCluster bootstrap layout assignment ---------------------------------

// assignLayoutSweep runs assignNewNodesToLayout against the shared layout fake
// with one Admin API fault at every call position, then retries fault-free. The
// cluster-controller layout path (gateway-only / bootstrap) must converge to the
// same layout regardless of where the first attempt died.
func assignLayoutSweep(t *testing.T, name string, initial []garage.LayoutNodeRole, nodes []bootstrapNodeInfo, cfg layoutConfig, wantRoles []string, wantAbsent []string) {
	t.Helper()
	type outcome struct {
		snap      string
		converged bool
		lastErr   error
		calls     int
		hit       bool
	}
	run := func(failAt int, after bool) outcome {
		fake := newFakeGarageLayout(initial...)
		srv := fake.server()
		defer srv.Close()
		proxy := newFaultProxy(t, srv.URL)
		gc := garage.NewClient(proxy.srv.URL, "test-token")
		ctx := context.Background()
		proxy.mu.Lock()
		proxy.failAt, proxy.after = failAt, after
		proxy.mu.Unlock()
		_ = assignNewNodesToLayout(ctx, gc, nodes, cfg)
		proxy.mu.Lock()
		proxy.failAt = 0
		proxy.mu.Unlock()
		var lastErr error
		converged := false
		for i := 0; i < 6; i++ {
			if lastErr = assignNewNodesToLayout(ctx, gc, nodes, cfg); lastErr == nil {
				converged = true
				break
			}
		}
		ok := converged
		for _, id := range wantRoles {
			ok = ok && fake.hasRole(id)
		}
		for _, id := range wantAbsent {
			ok = ok && !fake.hasRole(id)
		}
		// After convergence a further pass must be a no-op.
		before := layoutSnapshot(fake)
		_ = assignNewNodesToLayout(ctx, gc, nodes, cfg)
		if after := layoutSnapshot(fake); ok && after != before {
			t.Errorf("%s: steady-state pass changed layout: %s -> %s", name, before, after)
		}
		return outcome{snap: layoutSnapshot(fake), converged: ok, lastErr: lastErr, calls: proxy.calls, hit: proxy.hit}
	}
	base := run(0, false)
	if !base.converged {
		t.Fatalf("%s: baseline did not converge: %v (%s)", name, base.lastErr, base.snap)
	}
	t.Logf("%s: baseline garageCalls=%d state=%s", name, base.calls, base.snap)
	for i := 1; i <= base.calls; i++ {
		for _, after := range []bool{false, true} {
			got := run(i, after)
			if !got.hit {
				continue
			}
			if !got.converged {
				t.Errorf("%s [call #%d after=%v]: did not converge: %v (%s)", name, i, after, got.lastErr, got.snap)
			} else if got.snap != base.snap {
				t.Errorf("%s [call #%d after=%v]: end state diverged\n  baseline: %s\n  faulted:  %s", name, i, after, base.snap, got.snap)
			}
		}
	}
}

func TestFaultSweep_ClusterAssignNewNodes(t *testing.T) {
	ids := []string{
		"aa00000000000000000000000000000000000000000000000000000000000001",
		"bb00000000000000000000000000000000000000000000000000000000000002",
		"cc00000000000000000000000000000000000000000000000000000000000003",
	}
	nodes := []bootstrapNodeInfo{
		{id: ids[0], podName: "gc-0", tier: tierStorage},
		{id: ids[1], podName: "gc-1", tier: tierStorage},
		{id: ids[2], podName: "gc-gw-0", tier: tierGateway},
	}
	cfg := layoutConfig{
		zone: "z1", capacity: 100 << 30, replicationFactor: 2,
		clusterName: fiCluster, namespace: fiNS, clusterUID: "local-cluster-uid",
	}
	assignLayoutSweep(t, "assign-new-nodes", nil, nodes, cfg, ids, nil)
}

func TestFaultSweep_ClusterAssignStaleAndDrift(t *testing.T) {
	live := "aa00000000000000000000000000000000000000000000000000000000000001"
	stale := "dd00000000000000000000000000000000000000000000000000000000000004"
	cp := uint64(50 << 30)
	nodes := []bootstrapNodeInfo{{id: live, podName: "gc-0", tier: tierStorage}}
	cfg := layoutConfig{
		zone: "z1", capacity: 100 << 30, replicationFactor: 1,
		clusterName: fiCluster, namespace: fiNS, clusterUID: "local-cluster-uid",
	}
	tags := buildNodeTags(fiCluster, fiNS, tierStorage, nil, "gc-0", "local-cluster-uid")
	initial := []garage.LayoutNodeRole{
		// capacity drift: layout says 50Gi, desired 100Gi
		{ID: live, Zone: "z1", Tags: tags, Capacity: &cp},
		// stale node owned by this cluster UID, no longer running
		{ID: stale, Zone: "z1", Tags: buildNodeTags(fiCluster, fiNS, tierStorage, nil, "gc-9", "local-cluster-uid"), Capacity: &cp},
	}
	assignLayoutSweep(t, "assign-stale-drift", initial, nodes, cfg, []string{live}, []string{stale})
}

// -- GarageAdminToken (Kubernetes-only static bootstrap Secret) -----------------

func adminTokenScenario(name string, deleting bool, cluster func(c *garagev1beta2.GarageCluster)) faultScenario {
	return faultScenario{
		name: name,
		build: func(t *testing.T, kf *kubeFaults, gf *fakeGarage, scheme *runtime.Scheme) *faultEnv {
			token := &garagev1beta1.GarageAdminToken{
				ObjectMeta: metav1.ObjectMeta{Name: "boot-token", Namespace: fiNS, UID: "token-uid"},
				Spec:       garagev1beta1.GarageAdminTokenSpec{ClusterRef: garagev1beta1.ClusterReference{Name: fiCluster}},
			}
			gc := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: fiCluster, Namespace: fiNS, UID: "cluster-uid"},
				Spec: garagev1beta2.GarageClusterSpec{Admin: &garagev1beta2.AdminConfig{
					AdminTokenSecretRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "boot-token"},
						Key:                  DefaultAdminTokenKey,
					},
				}},
			}
			if cluster != nil {
				cluster(gc)
			}
			objs := []client.Object{token, gc}
			if deleting {
				now := metav1.NewTime(time.Now())
				token.DeletionTimestamp = &now
				token.Finalizers = []string{garageAdminTokenFinalizer}
				objs = append(objs, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "boot-token", Namespace: fiNS,
						OwnerReferences: []metav1.OwnerReference{{
							APIVersion: garagev1beta1.GroupVersion.String(), Kind: "GarageAdminToken", Name: "boot-token",
							UID: "token-uid", Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true),
						}},
					},
					Data: map[string][]byte{DefaultAdminTokenKey: []byte("x")},
				})
				// the cluster must have stopped consuming the source
				gc.Spec.Admin = nil
			}
			kube := newFaultKube(t, kf, scheme, objs...)
			r := &GarageAdminTokenReconciler{Client: kube, Scheme: scheme}
			nn := types.NamespacedName{Name: "boot-token", Namespace: fiNS}
			step := func(ctx context.Context) error {
				_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
				return err
			}
			return &faultEnv{
				step: step,
				done: func(ctx context.Context) bool {
					got := &garagev1beta1.GarageAdminToken{}
					err := kube.Get(ctx, nn, got)
					if deleting {
						return apierrors.IsNotFound(err)
					}
					return err == nil && got.Status.Phase == PhaseReady
				},
				observe: func(ctx context.Context) string {
					got := &garagev1beta1.GarageAdminToken{}
					out := ""
					if err := kube.Get(ctx, nn, got); err != nil {
						out = "token: " + err.Error()
					} else {
						out = fmt.Sprintf("phase=%s finalizers=%v hasDigest=%v secretRef=%v", got.Status.Phase, got.Finalizers, got.Status.TokenDigest != "", got.Status.SecretRef != nil)
					}
					sec := &corev1.Secret{}
					if err := kube.Get(ctx, nn, sec); err != nil {
						return out + " secret: " + err.Error()
					}
					digest := sec.Annotations[annotationStaticBootstrapTokenDigest]
					return out + fmt.Sprintf(" secret: keys=%v immutable=%v digestMatches=%v owners=%d", sortedKeys(sec.Data), sec.Immutable != nil && *sec.Immutable,
						digest == staticBootstrapTokenDigest(sec.Data[DefaultAdminTokenKey]), len(sec.OwnerReferences))
				},
			}
		},
		maxRetries: 12,
	}
}

func TestFaultSweep_GarageAdminTokenCreate(t *testing.T) {
	sweepFaults(t, adminTokenScenario("admintoken-create", false, nil))
}

func TestFaultSweep_GarageAdminTokenDelete(t *testing.T) {
	sweepFaults(t, adminTokenScenario("admintoken-delete", true, nil))
}

func TestFaultSweep_GarageNodeGatewayIdentityReplacement(t *testing.T) {
	const (
		liveID = "fa7874a6114eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		oldID  = "11111111f0e608c7737dde755727a45ca9b81414d76da011767fae2b867752fa"
		newID  = "73143814f0e608c7737dde755727a45ca9b81414d76da011767fae2b867752fa"
	)
	cp := uint64(700 << 30)
	live := garage.LayoutNodeRole{ID: liveID, Zone: testZone, Tags: []string{testTierStorageTag}, Capacity: &cp}
	old := garage.LayoutNodeRole{ID: oldID, Zone: testZone, Tags: []string{testTierGatewayTag}}
	nodeLayoutSweep(t, "node-gateway-identity-replacement", func() *garagev1beta1.GarageNode {
		return &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "gw-replace", Generation: 1},
			Spec: garagev1beta1.GarageNodeSpec{
				NodeID: newID, Zone: testZone, Gateway: true, Tags: []string{testTierGatewayTag},
			},
			Status: garagev1beta1.GarageNodeStatus{NodeID: oldID},
		}
	}, []garage.LayoutNodeRole{live, old}, newID, false)
}

func TestFaultSweep_GarageNodeFinalizeGatewayRole(t *testing.T) {
	const (
		liveID = "fa7874a6114eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		gwID   = "73143814f0e608c7737dde755727a45ca9b81414d76da011767fae2b867752fa"
	)
	cp := uint64(700 << 30)
	live := garage.LayoutNodeRole{ID: liveID, Zone: testZone, Tags: []string{testTierStorageTag}, Capacity: &cp}
	gw := garage.LayoutNodeRole{ID: gwID, Zone: testZone, Tags: []string{testTierGatewayTag}}
	nodeLayoutSweep(t, "node-finalize-gateway", func() *garagev1beta1.GarageNode {
		return &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "gw-del", Generation: 1},
			Spec: garagev1beta1.GarageNodeSpec{
				NodeID: gwID, Zone: testZone, Gateway: true, Tags: []string{testTierGatewayTag},
			},
			Status: garagev1beta1.GarageNodeStatus{NodeID: gwID},
		}
	}, []garage.LayoutNodeRole{live, gw}, gwID, true, true)
}

func TestFaultSweep_GarageNodeRoleDrift(t *testing.T) {
	const (
		liveID = "fa7874a6114eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		curID  = "73143814f0e608c7737dde755727a45ca9b81414d76da011767fae2b867752fa"
	)
	cp := uint64(700 << 30)
	smaller := uint64(300 << 30)
	live := garage.LayoutNodeRole{ID: liveID, Zone: testZone, Tags: []string{testTierStorageTag}, Capacity: &cp}
	cur := garage.LayoutNodeRole{ID: curID, Zone: testZone, Tags: []string{testTierStorageTag}, Capacity: &smaller}
	nodeLayoutSweep(t, "node-role-capacity-drift", func() *garagev1beta1.GarageNode {
		return &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "drift", Generation: 1},
			Spec: garagev1beta1.GarageNodeSpec{
				NodeID: curID, Zone: testZone,
				Capacity: resource.NewQuantity(700<<30, resource.BinarySI),
				Tags:     []string{testTierStorageTag},
			},
			Status: garagev1beta1.GarageNodeStatus{NodeID: curID},
		}
	}, []garage.LayoutNodeRole{live, cur}, curID, false)
}

// -- Double faults: the recovery from the first failure is itself interrupted ----

func TestFaultDouble_GarageKeyCreate(t *testing.T) {
	sweepDoubleFaults(t, keyScenario("key-create-double", nil, nil, false))
}

func TestFaultDouble_GarageBucketCreate(t *testing.T) {
	sweepDoubleFaults(t, bucketScenario("bucket-create-double", func(b *garagev1beta1.GarageBucket) {
		b.Spec.GlobalAlias = "bucket-one"
	}, nil, false))
}

func TestFaultDouble_GarageKeyImport(t *testing.T) {
	sweepDoubleFaults(t, keyScenario("key-import-double", func(k *garagev1beta1.GarageKey) {
		k.Spec.ImportKey = &garagev1beta1.ImportKeyConfig{
			AccessKeyID:     "GK0123456789abcdef01234567",
			SecretAccessKey: strings.Repeat("a1", 32),
		}
	}, nil, false))
}
