/*
Copyright 2026.

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

package v1beta2

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

const (
	extrasImage     = "busybox:1.37"
	extrasSidecar   = "ddns"
	extrasStateVol  = "ddns-state"
	extrasContainer = `{"name":"ddns","image":"busybox:1.37","volumeMounts":[{"name":"ddns-state","mountPath":"/var/lib/ddns"}]}`
	extrasVolume    = `{"name":"ddns-state","emptyDir":{}}`
)

func extraContainerFromJSON(t *testing.T, raw string) PodExtraContainer {
	t.Helper()
	var c PodExtraContainer
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	return c
}

func extraVolumeFromJSON(t *testing.T, raw string) PodExtraVolume {
	t.Helper()
	var v PodExtraVolume
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	return v
}

func TestPodExtraContainerLenientUnmarshalStrictResolve(t *testing.T) {
	const raw = `{"name":"ddns","image":"busybox:1.37","bogusField":true}`
	c := extraContainerFromJSON(t, raw)
	if c.Name != extrasSidecar {
		t.Fatalf("Name = %q, want %q", c.Name, extrasSidecar)
	}
	out, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != raw {
		t.Fatalf("unknown field did not survive a lenient round trip: %s", out)
	}
	if _, err := c.Resolve(); err == nil || !strings.Contains(err.Error(), "bogusField") {
		t.Fatalf("Resolve must reject the unknown field, got %v", err)
	}
}

func TestPodExtraContainerResolveJoinsAllStrictErrors(t *testing.T) {
	// One unknown field and one duplicate field: both come back in one error.
	c := extraContainerFromJSON(t, `{"name":"ddns","image":"a","image":"b","bogus":1}`)
	_, err := c.Resolve()
	if err == nil {
		t.Fatal("Resolve accepted unknown and duplicate fields")
	}
	for _, want := range []string{"bogus", "duplicate"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("joined error %q does not mention %q", err, want)
		}
	}
}

func TestPodExtraContainerResolveRejectsNonObjectsAndEmpty(t *testing.T) {
	for name, raw := range map[string]string{"null": `null`, "string": `"x"`, "array": `[]`} {
		c := extraContainerFromJSON(t, raw)
		if _, err := c.Resolve(); err == nil {
			t.Errorf("%s: Resolve accepted a non-object", name)
		}
	}
	if _, err := (PodExtraContainer{Name: "x"}).Resolve(); err == nil {
		t.Error("Resolve accepted a value built without a payload")
	}
	// Wrong type for a field: lenient unmarshal keeps it, Resolve rejects it.
	c := extraContainerFromJSON(t, `{"name":"ddns","image":7}`)
	if _, err := c.Resolve(); err == nil {
		t.Error("Resolve accepted image: 7")
	}
	// A non-string name leaves Name empty without failing the decoder.
	c = extraContainerFromJSON(t, `{"name":7,"image":"a"}`)
	if c.Name != "" {
		t.Errorf("Name = %q for a numeric name", c.Name)
	}
}

func TestPodExtraWrappersMarshalNameOnlyWithoutPayload(t *testing.T) {
	b, err := json.Marshal(PodExtraContainer{Name: "x"})
	if err != nil || string(b) != `{"name":"x"}` {
		t.Fatalf("Marshal = %s, %v", b, err)
	}
	b, err = json.Marshal(PodExtraVolume{Name: "v"})
	if err != nil || string(b) != `{"name":"v"}` {
		t.Fatalf("Marshal = %s, %v", b, err)
	}
}

func TestPodExtraDeepCopyDoesNotAliasRaw(t *testing.T) {
	orig := extraContainerFromJSON(t, extrasContainer)
	cp := orig.DeepCopy()
	cp.raw[2] = 'X'
	if string(orig.raw) != extrasContainer {
		t.Fatalf("DeepCopy aliases the raw payload: %s", orig.raw)
	}
	var nilContainer *PodExtraContainer
	if nilContainer.DeepCopy() != nil {
		t.Fatal("DeepCopy of nil must be nil")
	}

	origVol := extraVolumeFromJSON(t, extrasVolume)
	cpVol := origVol.DeepCopy()
	cpVol.raw[2] = 'X'
	if string(origVol.raw) != extrasVolume {
		t.Fatalf("volume DeepCopy aliases the raw payload: %s", origVol.raw)
	}
	var nilVolume *PodExtraVolume
	if nilVolume.DeepCopy() != nil {
		t.Fatal("DeepCopy of nil must be nil")
	}

	// The generated deepcopy of a template goes through the same methods.
	tpl := PodTemplate{InitContainers: []PodExtraContainer{orig}, ExtraVolumes: []PodExtraVolume{origVol}}
	tplCopy := tpl.DeepCopy()
	tplCopy.InitContainers[0].raw[2] = 'Y'
	tplCopy.ExtraVolumes[0].raw[2] = 'Y'
	if string(tpl.InitContainers[0].raw) != extrasContainer || string(tpl.ExtraVolumes[0].raw) != extrasVolume {
		t.Fatal("PodTemplate.DeepCopy aliases wrapper payloads")
	}
}

func TestNewPodExtraRoundTripsThroughResolve(t *testing.T) {
	want := corev1.Container{
		Name: extrasSidecar, Image: extrasImage, Command: []string{"sh", "-c", "sleep 1"},
		VolumeMounts: []corev1.VolumeMount{{Name: extrasStateVol, MountPath: "/state"}},
	}
	wrapped := NewPodExtraContainer(want)
	if wrapped.Name != want.Name {
		t.Fatalf("Name = %q", wrapped.Name)
	}
	got, err := wrapped.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip changed the container:\n got %#v\nwant %#v", got, want)
	}
	// And through a JSON encode/decode of the wrapper, as the API server does.
	b, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	var decoded PodExtraContainer
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	got, err = decoded.Resolve()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("JSON round trip: %v %#v", err, got)
	}

	vol := corev1.Volume{Name: extrasStateVol, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}
	gotVol, err := NewPodExtraVolume(vol).Resolve()
	if err != nil || !reflect.DeepEqual(gotVol, vol) {
		t.Fatalf("volume round trip: %v %#v", err, gotVol)
	}
	if containers := NewPodExtraContainers(nil); containers != nil {
		t.Fatal("NewPodExtraContainers(nil) must be nil")
	}
	if volumes := NewPodExtraVolumes(nil); volumes != nil {
		t.Fatal("NewPodExtraVolumes(nil) must be nil")
	}
}

func TestResolvePodExtraListsAggregateIndexedErrors(t *testing.T) {
	list := []PodExtraContainer{
		extraContainerFromJSON(t, `{"name":"ok","image":"a"}`),
		extraContainerFromJSON(t, `{"name":"bad1","image":"a","x":1}`),
		extraContainerFromJSON(t, `{"name":"bad2","image":"a","y":1}`),
	}
	_, err := ResolvePodExtraContainers("spec.storage.extraContainers", list)
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"extraContainers[1]", "extraContainers[2]", `"bad1"`, `"bad2"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "extraContainers[0]") {
		t.Errorf("error %q blames the valid item", err)
	}
	if got, err := ResolvePodExtraContainers("f", nil); got != nil || err != nil {
		t.Fatalf("empty list = %v, %v", got, err)
	}
	vols := []PodExtraVolume{extraVolumeFromJSON(t, `{"name":"v","emptyDir":{},"z":1}`)}
	if _, err := ResolvePodExtraVolumes("f", vols); err == nil || !strings.Contains(err.Error(), "f[0]") {
		t.Fatalf("volume error = %v", err)
	}
	if got, err := ResolvePodExtraVolumes("f", nil); got != nil || err != nil {
		t.Fatalf("empty list = %v, %v", got, err)
	}
}

func TestPodExtrasReservedNames(t *testing.T) {
	for _, name := range []string{"garage", "purge-cluster-layout", "garage-operator-x", "garage-operator-"} {
		if !IsReservedPodExtraContainerName(name) {
			t.Errorf("container %q must be reserved", name)
		}
	}
	for _, name := range []string{"ddns", "garage2", "my-garage", "garage-op"} {
		if IsReservedPodExtraContainerName(name) {
			t.Errorf("container %q must not be reserved", name)
		}
	}
	for _, name := range []string{"config", "metadata", "data", "data-0", "data-12", "rpc-secret", "admin-token", "metrics-token"} {
		if !IsReservedPodExtraVolumeName(name) {
			t.Errorf("volume %q must be reserved", name)
		}
	}
	for _, name := range []string{"data-x", "data-", "mydata", "data-1a", "ddns-state"} {
		if IsReservedPodExtraVolumeName(name) {
			t.Errorf("volume %q must not be reserved", name)
		}
	}
}

type extrasCase struct {
	name       string
	in         PodExtrasInput
	wantReason string // empty => valid
	wantText   string
}

func TestResolvePodExtrasTable(t *testing.T) {
	c := func(raw string) []PodExtraContainer { return []PodExtraContainer{extraContainerFromJSON(t, raw)} }
	v := func(raw string) []PodExtraVolume { return []PodExtraVolume{extraVolumeFromJSON(t, raw)} }
	ports := map[int32]string{3900: "S3 API", 3901: "RPC"}
	cases := []extrasCase{
		{name: "empty", in: PodExtrasInput{Field: "spec.storage"}},
		{name: "valid sidecar with volume", in: PodExtrasInput{
			Field: "spec.storage", ExtraContainers: c(extrasContainer), ExtraVolumes: v(extrasVolume),
		}},
		{name: "native sidecar init", in: PodExtrasInput{
			Field: "spec.storage", InitContainers: c(`{"name":"vip","image":"a","restartPolicy":"Always"}`),
		}},
		{name: "unknown field is a decode error", in: PodExtrasInput{
			Field: "spec.storage", ExtraContainers: c(`{"name":"x","image":"a","volumeMount":[]}`),
		}, wantReason: PodExtrasReasonDecodeError, wantText: "volumeMount"},
		{name: "unknown volume field", in: PodExtrasInput{
			Field: "spec.storage", ExtraVolumes: v(`{"name":"x","emptyDir":{},"nope":1}`),
		}, wantReason: PodExtrasReasonDecodeError, wantText: "nope"},
		{name: "reserved container name", in: PodExtrasInput{
			Field: "spec.storage", ExtraContainers: c(`{"name":"garage","image":"a"}`),
		}, wantReason: PodExtrasReasonReservedName},
		{name: "reserved prefix", in: PodExtrasInput{
			Field: "spec.storage", InitContainers: c(`{"name":"garage-operator-x","image":"a"}`),
		}, wantReason: PodExtrasReasonReservedName},
		{name: "invalid DNS label", in: PodExtrasInput{
			Field: "spec.storage", ExtraContainers: c(`{"name":"Bad_Name","image":"a"}`),
		}, wantReason: PodExtrasReasonInvalidContainer, wantText: "DNS-1123"},
		{name: "cross-list duplicate", in: PodExtrasInput{
			Field: "spec.storage", InitContainers: c(`{"name":"dup","image":"a"}`), ExtraContainers: c(`{"name":"dup","image":"a"}`),
		}, wantReason: PodExtrasReasonInvalidContainer, wantText: "unique across"},
		{name: "missing image", in: PodExtrasInput{
			Field: "spec.storage", ExtraContainers: c(`{"name":"x"}`),
		}, wantReason: PodExtrasReasonInvalidContainer, wantText: "image is required"},
		{name: "extra container restartPolicy", in: PodExtrasInput{
			Field: "spec.storage", ExtraContainers: c(`{"name":"x","image":"a","restartPolicy":"Always"}`),
		}, wantReason: PodExtrasReasonInvalidContainer, wantText: "restartPolicy"},
		{name: "init restartPolicy other than Always", in: PodExtrasInput{
			Field: "spec.storage", InitContainers: c(`{"name":"x","image":"a","restartPolicy":"Never"}`),
		}, wantReason: PodExtrasReasonInvalidContainer, wantText: "restartPolicy"},
		{name: "volumeDevices", in: PodExtrasInput{
			Field: "spec.storage", ExtraContainers: c(`{"name":"x","image":"a","volumeDevices":[{"name":"b","devicePath":"/dev/x"}]}`),
		}, wantReason: PodExtrasReasonInvalidContainer, wantText: "block devices"},
		{name: "hostPort", in: PodExtrasInput{
			Field: "spec.storage", ExtraContainers: c(`{"name":"x","image":"a","ports":[{"containerPort":8080,"hostPort":8080}]}`),
		}, wantReason: PodExtrasReasonInvalidContainer, wantText: "hostPort"},
		{name: "port collides with S3", in: PodExtrasInput{
			Field: "spec.storage", ExtraContainers: c(`{"name":"x","image":"a","ports":[{"containerPort":3900}]}`), ListenerPorts: ports,
		}, wantReason: PodExtrasReasonInvalidContainer, wantText: "S3 API"},
		{name: "explicit TCP collides", in: PodExtrasInput{
			Field: "spec.storage", ExtraContainers: c(`{"name":"x","image":"a","ports":[{"containerPort":3901,"protocol":"TCP"}]}`), ListenerPorts: ports,
		}, wantReason: PodExtrasReasonInvalidContainer, wantText: "RPC"},
		{name: "UDP on a listener port does not collide", in: PodExtrasInput{
			Field: "spec.storage", ExtraContainers: c(`{"name":"x","image":"a","ports":[{"containerPort":3900,"protocol":"UDP"}]}`), ListenerPorts: ports,
		}},
		{name: "port out of range", in: PodExtrasInput{
			Field: "spec.storage", ExtraContainers: c(`{"name":"x","image":"a","ports":[{"containerPort":70000}]}`),
		}, wantReason: PodExtrasReasonInvalidContainer, wantText: "between 1 and 65535"},
		{name: "mount of metadata names node_key", in: PodExtrasInput{
			Field: "spec.storage", ExtraContainers: c(`{"name":"x","image":"a","volumeMounts":[{"name":"metadata","mountPath":"/m"}]}`),
		}, wantReason: PodExtrasReasonOperatorVolumeMount, wantText: "node_key"},
		{name: "mount of data-3", in: PodExtrasInput{
			Field: "spec.storage", InitContainers: c(`{"name":"x","image":"a","volumeMounts":[{"name":"data-3","mountPath":"/m"}]}`),
		}, wantReason: PodExtrasReasonOperatorVolumeMount},
		{name: "mount of undeclared volume", in: PodExtrasInput{
			Field: "spec.storage", ExtraContainers: c(`{"name":"x","image":"a","volumeMounts":[{"name":"nope","mountPath":"/m"}]}`),
		}, wantReason: PodExtrasReasonUnknownVolume},
		{name: "undeclared mount tolerated when set is unknown", in: PodExtrasInput{
			Field: "spec", ExtraContainers: c(`{"name":"x","image":"a","volumeMounts":[{"name":"nope","mountPath":"/m"}]}`),
			SkipUnknownMountCheck: true,
		}},
		{name: "operator mount still rejected when set is unknown", in: PodExtrasInput{
			Field: "spec", ExtraContainers: c(`{"name":"x","image":"a","volumeMounts":[{"name":"config","mountPath":"/m"}]}`),
			SkipUnknownMountCheck: true,
		}, wantReason: PodExtrasReasonOperatorVolumeMount},
		{name: "mountable override", in: PodExtrasInput{
			Field: "spec", ExtraContainers: c(`{"name":"x","image":"a","volumeMounts":[{"name":"ddns-state","mountPath":"/m"}]}`),
			MountableVolumes: v(extrasVolume),
		}},
		{name: "reserved volume name", in: PodExtrasInput{
			Field: "spec.storage", ExtraVolumes: v(`{"name":"metadata","emptyDir":{}}`),
		}, wantReason: PodExtrasReasonReservedName},
		{name: "data-x volume is allowed", in: PodExtrasInput{
			Field: "spec.storage", ExtraVolumes: v(`{"name":"data-x","emptyDir":{}}`),
		}},
		{name: "duplicate volume", in: PodExtrasInput{
			Field: "spec.storage", ExtraVolumes: []PodExtraVolume{
				extraVolumeFromJSON(t, `{"name":"a","emptyDir":{}}`), extraVolumeFromJSON(t, `{"name":"a","emptyDir":{}}`),
			},
		}, wantReason: PodExtrasReasonInvalidContainer, wantText: "duplicate volume"},
		{name: "volume without a source", in: PodExtrasInput{
			Field: "spec.storage", ExtraVolumes: v(`{"name":"a"}`),
		}, wantReason: PodExtrasReasonInvalidContainer, wantText: "exactly one volume source"},
		{name: "volume with two sources", in: PodExtrasInput{
			Field: "spec.storage", ExtraVolumes: v(`{"name":"a","emptyDir":{},"hostPath":{"path":"/x"}}`),
		}, wantReason: PodExtrasReasonInvalidContainer, wantText: "exactly one volume source"},
		{name: "hostPath is allowed", in: PodExtrasInput{
			Field: "spec.storage", ExtraVolumes: v(`{"name":"a","hostPath":{"path":"/run/x"}}`),
		}},
		{name: "oversize", in: PodExtrasInput{
			Field: "spec.storage", ExtraContainers: c(`{"name":"x","image":"a","args":["` + strings.Repeat("a", MaxPodExtrasBytes) + `"]}`),
		}, wantReason: PodExtrasReasonInvalidContainer, wantText: "the limit is"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, issues := ResolvePodExtras(tc.in)
			if tc.wantReason == "" {
				if len(issues) != 0 {
					t.Fatalf("unexpected issues: %v", PodExtrasIssuesError(issues))
				}
				return
			}
			if len(issues) == 0 {
				t.Fatal("expected an issue")
			}
			found := false
			for _, issue := range issues {
				if issue.Reason == tc.wantReason && strings.Contains(issue.Error(), tc.wantText) &&
					strings.HasPrefix(issue.Path, tc.in.Field) {
					found = true
				}
			}
			if !found {
				t.Fatalf("no %s issue containing %q under %s: %v", tc.wantReason, tc.wantText, tc.in.Field, PodExtrasIssuesError(issues))
			}
		})
	}
}

func TestResolvePodExtrasNamesFieldPathAndIndex(t *testing.T) {
	_, issues := ResolvePodExtras(PodExtrasInput{
		Field: "spec.gateway",
		ExtraContainers: []PodExtraContainer{
			extraContainerFromJSON(t, `{"name":"ok","image":"a"}`),
			extraContainerFromJSON(t, `{"name":"bad","image":""}`),
		},
	})
	if len(issues) != 1 || issues[0].Path != "spec.gateway.extraContainers[1].image" {
		t.Fatalf("issues = %v", issues)
	}
	reasons := SortedPodExtrasReasons(issues)
	if len(reasons) != 1 || reasons[0] != PodExtrasReasonInvalidContainer {
		t.Fatalf("reasons = %v", reasons)
	}
	if PodExtrasIssuesError(nil) != nil {
		t.Fatal("no issues must be a nil error")
	}
}

func TestResolvePodExtrasReturnsResolvedValues(t *testing.T) {
	resolved, issues := ResolvePodExtras(PodExtrasInput{
		Field:           "spec.storage",
		InitContainers:  []PodExtraContainer{extraContainerFromJSON(t, `{"name":"i","image":"a"}`)},
		ExtraContainers: []PodExtraContainer{extraContainerFromJSON(t, extrasContainer)},
		ExtraVolumes:    []PodExtraVolume{extraVolumeFromJSON(t, extrasVolume)},
	})
	if len(issues) != 0 {
		t.Fatal(PodExtrasIssuesError(issues))
	}
	if resolved.IsEmpty() || len(resolved.InitContainers) != 1 || len(resolved.ExtraContainers) != 1 || len(resolved.ExtraVolumes) != 1 {
		t.Fatalf("resolved = %#v", resolved)
	}
	if resolved.ExtraContainers[0].VolumeMounts[0].MountPath != "/var/lib/ddns" {
		t.Fatalf("mount path lost: %#v", resolved.ExtraContainers[0])
	}
	if !(ResolvedPodExtras{}).IsEmpty() {
		t.Fatal("zero value must be empty")
	}
}

func TestGarageListenerPorts(t *testing.T) {
	cluster := &GarageCluster{Spec: GarageClusterSpec{}}
	got := cluster.GarageListenerPorts()
	for port, what := range map[int32]string{3900: "S3 API", 3901: "RPC", 3902: "web", 3903: "admin API"} {
		if got[port] != what {
			t.Errorf("default port %d = %q, want %q", port, got[port], what)
		}
	}
	if _, ok := got[3904]; ok {
		t.Error("K2V port must be absent unless configured")
	}
	disabled := false
	cluster.Spec.K2VAPI = &K2VAPIConfig{BindPort: 4000}
	cluster.Spec.WebAPI = &WebAPIConfig{Enabled: &disabled}
	cluster.Spec.S3API = &S3APIConfig{BindPort: 4100}
	got = cluster.GarageListenerPorts()
	if got[4000] != "K2V API" || got[4100] != "S3 API" {
		t.Errorf("configured ports missing: %v", got)
	}
	if _, ok := got[3902]; ok {
		t.Error("disabled web API must not reserve its port")
	}
	if _, ok := got[3900]; ok {
		t.Error("overridden S3 port must replace the default")
	}
}

func TestPodTemplateForNodeFollowsTierSelection(t *testing.T) {
	storage := &StorageSpec{PodTemplate: PodTemplate{PriorityClassName: "storage"}}
	gateway := &GatewaySpec{PodTemplate: PodTemplate{PriorityClassName: "gateway"}}
	both := &GarageCluster{Spec: GarageClusterSpec{Storage: storage, Gateway: gateway}}
	if got := both.PodTemplateForNode(true); got == nil || got.PriorityClassName != "gateway" {
		t.Fatalf("gateway node = %#v", got)
	}
	if got := both.PodTemplateForNode(false); got == nil || got.PriorityClassName != "storage" {
		t.Fatalf("storage node = %#v", got)
	}
	storageOnly := &GarageCluster{Spec: GarageClusterSpec{Storage: storage}}
	if got := storageOnly.PodTemplateForNode(true); got == nil || got.PriorityClassName != "storage" {
		t.Fatalf("gateway node on storage-only cluster = %#v", got)
	}
	gatewayOnly := &GarageCluster{Spec: GarageClusterSpec{Gateway: gateway}}
	if got := gatewayOnly.PodTemplateForNode(false); got == nil || got.PriorityClassName != "gateway" {
		t.Fatalf("storage node on gateway-only cluster = %#v", got)
	}
	if got := (&GarageCluster{}).PodTemplateForNode(false); got != nil {
		t.Fatalf("no tier = %#v", got)
	}
}

func podExtrasCluster() *GarageCluster {
	cluster := scalableStorageCluster("extras")
	return cluster
}

func TestClusterWebhookValidatesPodExtrasOnEveryTemplate(t *testing.T) {
	validator := &GarageClusterValidator{}
	bad := []PodExtraContainer{extraContainerFromJSON(t, `{"name":"x","image":"a","typo":1}`)}
	cases := map[string]func(*GarageCluster){
		"spec.storage.initContainers[0]":  func(c *GarageCluster) { c.Spec.Storage.InitContainers = bad },
		"spec.storage.extraContainers[0]": func(c *GarageCluster) { c.Spec.Storage.ExtraContainers = bad },
		"spec.gateway.extraContainers[0]": func(c *GarageCluster) {
			c.Spec.Gateway = &GatewaySpec{Replicas: 1}
			c.Spec.Gateway.ExtraContainers = bad
		},
		`spec.storage.nodeLocalPools["pool"].podTemplate.initContainers[0]`: func(c *GarageCluster) {
			pool := validDaemonSetCluster().Spec.Storage.NodeLocalPools[0]
			pool.Name = "pool"
			pool.PodTemplate = &NodeLocalPoolPodTemplate{InitContainers: bad}
			c.Spec.Storage.NodeLocalPools = []NodeLocalPoolSpec{pool}
		},
	}
	for path, mutate := range cases {
		t.Run(path, func(t *testing.T) {
			cluster := podExtrasCluster()
			mutate(cluster)
			_, err := validator.ValidateCreate(context.Background(), cluster)
			if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "typo") {
				t.Fatalf("ValidateCreate = %v, want a strict-decode error at %s", err, path)
			}
			old := podExtrasCluster()
			_, err = validator.ValidateUpdate(context.Background(), old, cluster)
			if err == nil || !strings.Contains(err.Error(), path) {
				t.Fatalf("ValidateUpdate = %v, want an error at %s", err, path)
			}
		})
	}

	valid := podExtrasCluster()
	valid.Spec.Storage.ExtraContainers = []PodExtraContainer{extraContainerFromJSON(t, extrasContainer)}
	valid.Spec.Storage.ExtraVolumes = []PodExtraVolume{extraVolumeFromJSON(t, extrasVolume)}
	if _, err := validator.ValidateCreate(context.Background(), valid); err != nil {
		t.Fatalf("valid extras rejected: %v", err)
	}
	// Configured listener ports are the ones a container may not claim.
	valid.Spec.S3API = &S3APIConfig{BindPort: 4100}
	valid.Spec.Storage.ExtraContainers = []PodExtraContainer{extraContainerFromJSON(t, `{"name":"x","image":"a","ports":[{"containerPort":4100}]}`)}
	valid.Spec.Storage.ExtraVolumes = nil
	if _, err := validator.ValidateCreate(context.Background(), valid); err == nil || !strings.Contains(err.Error(), "S3 API") {
		t.Fatalf("port collision with the configured S3 port accepted: %v", err)
	}
}

func TestStorageRolloutRecoveryTreatsRevertingExtrasAsWorkloadChange(t *testing.T) {
	// During an active storage rollout only workload fields may change. The pod
	// template carries the extras, so reverting a bad sidecar must stay possible.
	old := podExtrasCluster()
	old.Spec.Storage.ExtraContainers = []PodExtraContainer{extraContainerFromJSON(t, `{"name":"bad","image":"does-not-exist"}`)}
	old.Spec.Storage.NodeLocalPools = []NodeLocalPoolSpec{{Name: "p", PodTemplate: &NodeLocalPoolPodTemplate{ExtraContainers: []PodExtraContainer{extraContainerFromJSON(t, `{"name":"bad","image":"x"}`)}}}}
	reverted := old.DeepCopy()
	reverted.Spec.Storage.ExtraContainers = nil
	reverted.Spec.Storage.NodeLocalPools[0].PodTemplate = nil
	if !storageRolloutRecoverySafeSpecChange(old, reverted) {
		t.Fatal("reverting extras is not classified as a workload-only change")
	}
	topology := reverted.DeepCopy()
	topology.Spec.Storage.Replicas++
	if storageRolloutRecoverySafeSpecChange(old, topology) {
		t.Fatal("a topology change must stay frozen")
	}
}

func TestPodExtrasSampleIsValid(t *testing.T) {
	raw, err := os.ReadFile("../../config/samples/garage_v1beta2_garagecluster_pod_extras.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cluster := &GarageCluster{}
	if err := yaml.UnmarshalStrict(raw, cluster); err != nil {
		t.Fatalf("sample does not decode: %v", err)
	}
	if got := len(cluster.Spec.Storage.InitContainers) + len(cluster.Spec.Storage.ExtraContainers) + len(cluster.Spec.Storage.ExtraVolumes); got != 3 {
		t.Fatalf("sample should exercise all three lists, got %d entries", got)
	}
	if _, err := (&GarageClusterValidator{}).ValidateCreate(context.Background(), cluster); err != nil {
		t.Fatalf("sample rejected by the webhook: %v", err)
	}
}
