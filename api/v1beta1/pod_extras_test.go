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

package v1beta1

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

const (
	extrasSidecarJSON   = `{"name":"ddns","image":"busybox:1.37","volumeMounts":[{"name":"ddns-state","mountPath":"/var/lib/ddns"}]}`
	extrasInitJSON      = `{"name":"wait-for-vip","image":"busybox:1.37","command":["sh","-c","true"]}`
	extrasGatewayJSON   = `{"name":"gw-helper","image":"busybox:1.37"}`
	extrasPoolJSON      = `{"name":"pool-helper","image":"busybox:1.37"}`
	extrasVolumeJSON    = `{"name":"ddns-state","emptyDir":{}}`
	extrasTypoJSON      = `{"name":"x","image":"busybox:1.37","volumeMount":[]}`
	extrasBadMountJSON  = `{"name":"x","image":"busybox:1.37","volumeMounts":[{"name":"metadata","mountPath":"/m"}]}`
	extrasBootstrapPeer = "0123456789abcdef@10.0.0.1:3901"
)

func podExtraContainers(t *testing.T, raws ...string) []v1beta2.PodExtraContainer {
	t.Helper()
	out := make([]v1beta2.PodExtraContainer, 0, len(raws))
	for _, raw := range raws {
		var c v1beta2.PodExtraContainer
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatalf("unmarshal %s: %v", raw, err)
		}
		out = append(out, c)
	}
	return out
}

func podExtraVolumes(t *testing.T, raws ...string) []v1beta2.PodExtraVolume {
	t.Helper()
	out := make([]v1beta2.PodExtraVolume, 0, len(raws))
	for _, raw := range raws {
		var v v1beta2.PodExtraVolume
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			t.Fatalf("unmarshal %s: %v", raw, err)
		}
		out = append(out, v)
	}
	return out
}

// resolvedTemplate flattens a template's extras to typed values, so round trips
// compare Kubernetes semantics rather than raw bytes.
type resolvedTemplate struct {
	Init    []corev1.Container
	Extra   []corev1.Container
	Volumes []corev1.Volume
}

func resolveTemplate(t *testing.T, tpl *v1beta2.PodTemplate) resolvedTemplate {
	t.Helper()
	var out resolvedTemplate
	var err error
	if out.Init, err = v1beta2.ResolvePodExtraContainers("init", tpl.InitContainers); err != nil {
		t.Fatal(err)
	}
	if out.Extra, err = v1beta2.ResolvePodExtraContainers("extra", tpl.ExtraContainers); err != nil {
		t.Fatal(err)
	}
	if out.Volumes, err = v1beta2.ResolvePodExtraVolumes("volumes", tpl.ExtraVolumes); err != nil {
		t.Fatal(err)
	}
	return out
}

func assertSameExtras(t *testing.T, what string, got, want *v1beta2.PodTemplate) {
	t.Helper()
	g, w := resolveTemplate(t, got), resolveTemplate(t, want)
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("%s: extras changed in conversion:\n got %#v\nwant %#v", what, g, w)
	}
}

func storageHubWithExtras(t *testing.T) *v1beta2.GarageCluster {
	t.Helper()
	hub := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "extras", Namespace: testNS},
		Spec: v1beta2.GarageClusterSpec{
			Storage: &v1beta2.StorageSpec{
				Replicas: 3,
				Metadata: &v1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse(test10Gi))},
				Data:     &v1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
			},
		},
	}
	hub.Spec.Storage.InitContainers = podExtraContainers(t, extrasInitJSON)
	hub.Spec.Storage.ExtraContainers = podExtraContainers(t, extrasSidecarJSON)
	hub.Spec.Storage.ExtraVolumes = podExtraVolumes(t, extrasVolumeJSON)
	return hub
}

func edgeGatewayHubWithExtras(t *testing.T) *v1beta2.GarageCluster {
	t.Helper()
	hub := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: testNS},
		Spec: v1beta2.GarageClusterSpec{
			Gateway:   &v1beta2.GatewaySpec{Replicas: 2},
			ConnectTo: &v1beta2.ConnectToConfig{BootstrapPeers: []string{extrasBootstrapPeer}},
		},
	}
	hub.Spec.Gateway.InitContainers = podExtraContainers(t, extrasGatewayJSON)
	hub.Spec.Gateway.ExtraContainers = podExtraContainers(t, extrasSidecarJSON)
	hub.Spec.Gateway.ExtraVolumes = podExtraVolumes(t, extrasVolumeJSON)
	return hub
}

// viaJSON simulates a v1beta1 client: the API server serialises the spoke, the
// client decodes it into its typed struct and writes the same typed struct back.
func viaJSON(t *testing.T, in *GarageCluster) *GarageCluster {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	out := &GarageCluster{}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPodExtrasConvertFromStorageMapsToTopLevelFields(t *testing.T) {
	hub := storageHubWithExtras(t)
	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(hub); err != nil {
		t.Fatal(err)
	}
	if len(spoke.Spec.InitContainers) != 1 || len(spoke.Spec.ExtraContainers) != 1 || len(spoke.Spec.ExtraVolumes) != 1 {
		t.Fatalf("storage extras did not reach the v1beta1 top-level fields: %#v", spoke.Spec)
	}
	if spoke.Annotations[v1beta2AnnotationGatewayTierData] != "" {
		t.Fatal("a storage-only cluster must not carry a gateway payload")
	}
}

func TestPodExtrasRoundTripStorage(t *testing.T) {
	hub := storageHubWithExtras(t)
	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(hub); err != nil {
		t.Fatal(err)
	}
	back := &v1beta2.GarageCluster{}
	if err := viaJSON(t, spoke).ConvertTo(back); err != nil {
		t.Fatal(err)
	}
	assertSameExtras(t, "storage", &back.Spec.Storage.PodTemplate, &hub.Spec.Storage.PodTemplate)
	if back.Spec.Gateway != nil {
		t.Fatal("round trip invented a gateway tier")
	}
}

func TestPodExtrasRoundTripEdgeGateway(t *testing.T) {
	hub := edgeGatewayHubWithExtras(t)
	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(hub); err != nil {
		t.Fatal(err)
	}
	if !spoke.Spec.Gateway || len(spoke.Spec.InitContainers) != 1 || len(spoke.Spec.ExtraContainers) != 1 || len(spoke.Spec.ExtraVolumes) != 1 {
		t.Fatalf("edge gateway extras did not reach the v1beta1 top-level fields: %#v", spoke.Spec)
	}
	// The extras are representable in v1beta1, so no reserved payload is needed.
	if spoke.Annotations[v1beta2AnnotationGatewayTierData] != "" {
		t.Fatalf("edge gateway with only extras must not need the v1beta2 payload: %v", spoke.Annotations)
	}
	back := &v1beta2.GarageCluster{}
	if err := viaJSON(t, spoke).ConvertTo(back); err != nil {
		t.Fatal(err)
	}
	if back.Spec.Storage != nil {
		t.Fatal("round trip invented a storage tier")
	}
	assertSameExtras(t, "edge gateway", &back.Spec.Gateway.PodTemplate, &hub.Spec.Gateway.PodTemplate)
}

func TestPodExtrasRoundTripUnifiedKeepsBothTiersApart(t *testing.T) {
	hub := storageHubWithExtras(t)
	hub.Spec.Gateway = &v1beta2.GatewaySpec{Replicas: 2}
	hub.Spec.Gateway.InitContainers = podExtraContainers(t, extrasGatewayJSON)
	hub.Spec.Gateway.ExtraContainers = nil
	hub.Spec.Gateway.ExtraVolumes = podExtraVolumes(t, `{"name":"gw-scratch","emptyDir":{}}`)

	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(hub); err != nil {
		t.Fatal(err)
	}
	// Top-level fields are the storage tier's; the gateway tier's lists ride in
	// the reserved payload.
	if spoke.Spec.InitContainers[0].Name != "wait-for-vip" || spoke.Spec.ExtraVolumes[0].Name != "ddns-state" {
		t.Fatalf("top-level lists are not the storage tier's: %#v", spoke.Spec)
	}
	payload := spoke.Annotations[v1beta2AnnotationGatewayTierData]
	if !strings.Contains(payload, "gw-helper") || !strings.Contains(payload, "gw-scratch") {
		t.Fatalf("gateway payload lost the gateway tier's lists: %s", payload)
	}
	back := &v1beta2.GarageCluster{}
	if err := viaJSON(t, spoke).ConvertTo(back); err != nil {
		t.Fatal(err)
	}
	assertSameExtras(t, "unified storage", &back.Spec.Storage.PodTemplate, &hub.Spec.Storage.PodTemplate)
	assertSameExtras(t, "unified gateway", &back.Spec.Gateway.PodTemplate, &hub.Spec.Gateway.PodTemplate)
}

func TestPodExtrasRoundTripEdgeGatewayWithPayloadMergesTopLevelEdits(t *testing.T) {
	// An edge gateway that needs the payload for another v1beta2-only field
	// still takes its extras from the editable top-level fields.
	hub := edgeGatewayHubWithExtras(t)
	hub.Spec.Gateway.Env = []corev1.EnvVar{{Name: "EXAMPLE", Value: "1"}}
	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(hub); err != nil {
		t.Fatal(err)
	}
	if spoke.Annotations[v1beta2AnnotationGatewayTierData] == "" {
		t.Fatal("gateway env must force the payload")
	}
	edited := viaJSON(t, spoke)
	edited.Spec.ExtraContainers = podExtraContainers(t, `{"name":"replaced","image":"busybox:1.37"}`)
	back := &v1beta2.GarageCluster{}
	if err := edited.ConvertTo(back); err != nil {
		t.Fatal(err)
	}
	if got := back.Spec.Gateway.ExtraContainers; len(got) != 1 || got[0].Name != "replaced" {
		t.Fatalf("top-level edit lost behind the payload: %#v", got)
	}
	if len(back.Spec.Gateway.Env) != 1 {
		t.Fatal("v1beta2-only env lost")
	}
}

func TestPodExtrasRoundTripNodeLocalPools(t *testing.T) {
	hub := nodeLocalPoolHub()
	hub.Spec.Storage.NodeLocalPools[0].PodTemplate = &v1beta2.NodeLocalPoolPodTemplate{
		InitContainers:  podExtraContainers(t, extrasPoolJSON),
		ExtraContainers: podExtraContainers(t, extrasSidecarJSON),
		ExtraVolumes:    podExtraVolumes(t, extrasVolumeJSON),
	}
	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(hub); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(spoke.Annotations[v1beta2AnnotationNodeLocalPoolsData], "pool-helper") {
		t.Fatal("pool extras were not carried by the transport annotation")
	}
	back := &v1beta2.GarageCluster{}
	if err := viaJSON(t, spoke).ConvertTo(back); err != nil {
		t.Fatal(err)
	}
	want, got := hub.Spec.Storage.NodeLocalPools[0].PodTemplate, back.Spec.Storage.NodeLocalPools[0].PodTemplate
	if got == nil {
		t.Fatal("pool podTemplate lost")
	}
	assertSameExtras(t, "pool",
		&v1beta2.PodTemplate{InitContainers: got.InitContainers, ExtraContainers: got.ExtraContainers, ExtraVolumes: got.ExtraVolumes},
		&v1beta2.PodTemplate{InitContainers: want.InitContainers, ExtraContainers: want.ExtraContainers, ExtraVolumes: want.ExtraVolumes})
}

func TestPodExtrasLossyWriteDoesNotClearHubValues(t *testing.T) {
	// The reason v1beta1 carries typed mirrors (design D4): a v1beta1 client that
	// reads the object and writes it back must not erase the extras. Without the
	// mirror fields the hub would be rebuilt from a spoke that never saw them.
	hub := storageHubWithExtras(t)
	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(hub); err != nil {
		t.Fatal(err)
	}
	// An unrelated edit through v1beta1.
	client := viaJSON(t, spoke)
	client.Spec.Replicas = 5
	back := &v1beta2.GarageCluster{}
	if err := client.ConvertTo(back); err != nil {
		t.Fatal(err)
	}
	if back.Spec.Storage.Replicas != 5 {
		t.Fatal("unrelated edit lost")
	}
	assertSameExtras(t, "unrelated v1beta1 write", &back.Spec.Storage.PodTemplate, &hub.Spec.Storage.PodTemplate)
}

func TestPodExtrasUnknownFieldsSurviveConversion(t *testing.T) {
	// Conversion is lenient: a malformed extra must reach the strict checks
	// (webhook, controller) rather than be dropped or stall conversion.
	hub := storageHubWithExtras(t)
	hub.Spec.Storage.ExtraContainers = podExtraContainers(t, extrasTypoJSON)
	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(hub); err != nil {
		t.Fatal(err)
	}
	back := &v1beta2.GarageCluster{}
	if err := viaJSON(t, spoke).ConvertTo(back); err != nil {
		t.Fatal(err)
	}
	if _, err := back.Spec.Storage.ExtraContainers[0].Resolve(); err == nil || !strings.Contains(err.Error(), "volumeMount") {
		t.Fatalf("unknown field was dropped or tolerated by conversion: %v", err)
	}
}

func TestGatewayTierRequiresPayloadAccountsForExtras(t *testing.T) {
	hub := edgeGatewayHubWithExtras(t)
	spoke := &GarageCluster{}
	if err := spoke.ConvertFrom(hub); err != nil {
		t.Fatal(err)
	}
	// The v1beta1 view carries the extras, so the projected gateway equals the
	// real one and no payload is needed.
	if gatewayTierRequiresV1Beta2Payload(hub.Spec.Gateway, spoke) {
		t.Fatal("extras alone must be representable without the payload")
	}
	// If the view lost them the gateway would differ from its projection, and
	// the full payload would be required instead of silently dropping them.
	spoke.Spec.ExtraContainers = nil
	if !gatewayTierRequiresV1Beta2Payload(hub.Spec.Gateway, spoke) {
		t.Fatal("a view without the gateway's extras must not be treated as representable")
	}
}

func podExtrasSpoke() *GarageCluster {
	return &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "extras", Namespace: testWebhookNS},
		Spec: GarageClusterSpec{
			Replicas: 1,
			Storage: StorageConfig{
				Metadata: &VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
				Data:     &VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
			},
			Replication: &ReplicationConfig{Factor: 1},
		},
	}
}

func TestV1Beta1ClusterWebhookValidatesPodExtras(t *testing.T) {
	validator := &GarageClusterValidator{}
	ctx := context.Background()

	valid := podExtrasSpoke()
	valid.Spec.ExtraContainers = podExtraContainers(t, extrasSidecarJSON)
	valid.Spec.ExtraVolumes = podExtraVolumes(t, extrasVolumeJSON)
	valid.Spec.InitContainers = podExtraContainers(t, extrasInitJSON)
	if _, err := validator.ValidateCreate(ctx, valid); err != nil {
		t.Fatalf("valid extras rejected: %v", err)
	}

	cases := map[string]struct {
		mutate func(*GarageCluster)
		want   string
	}{
		"unknown field": {func(c *GarageCluster) { c.Spec.ExtraContainers = podExtraContainers(t, extrasTypoJSON) }, "volumeMount"},
		"metadata mount": {func(c *GarageCluster) {
			c.Spec.InitContainers = podExtraContainers(t, extrasBadMountJSON)
		}, "node_key"},
		"reserved name": {func(c *GarageCluster) {
			c.Spec.ExtraContainers = podExtraContainers(t, `{"name":"garage","image":"a"}`)
		}, "operator-reserved"},
		"cross-list duplicate": {func(c *GarageCluster) {
			c.Spec.InitContainers = podExtraContainers(t, `{"name":"dup","image":"a"}`)
			c.Spec.ExtraContainers = podExtraContainers(t, `{"name":"dup","image":"a"}`)
		}, "unique across"},
		"port collision": {func(c *GarageCluster) {
			c.Spec.S3API = &S3APIConfig{BindPort: 4100}
			c.Spec.ExtraContainers = podExtraContainers(t, `{"name":"x","image":"a","ports":[{"containerPort":4100}]}`)
		}, "S3 API"},
		"preserved gateway payload": {func(c *GarageCluster) {
			c.Annotations = map[string]string{
				v1beta2AnnotationGatewayTierData: `{"replicas":1,"extraContainers":[` + extrasTypoJSON + `]}`,
			}
		}, "volumeMount"},
		"preserved pool payload": {func(c *GarageCluster) {
			c.Annotations = map[string]string{
				v1beta2AnnotationNodeLocalPoolsData: `[{"name":"p","podTemplate":{"initContainers":[` + extrasTypoJSON + `]}}]`,
			}
		}, "volumeMount"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cluster := podExtrasSpoke()
			tc.mutate(cluster)
			if _, err := validator.ValidateCreate(ctx, cluster); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateCreate = %v, want an error containing %q", err, tc.want)
			}
			if err := cluster.validatePodExtras(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validatePodExtras = %v, want an error containing %q", err, tc.want)
			}
			if len(cluster.Annotations) > 0 {
				// Reserved payloads have their own preservation rules on update.
				return
			}
			if _, err := validator.ValidateUpdate(ctx, podExtrasSpoke(), cluster); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateUpdate = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestV1Beta1RolloutRecoveryTreatsExtrasAsWorkloadFields(t *testing.T) {
	old := podExtrasSpoke()
	old.Spec.ExtraContainers = podExtraContainers(t, `{"name":"bad","image":"does-not-exist"}`)
	reverted := old.DeepCopy()
	reverted.Spec.ExtraContainers = nil
	if !v1beta1StorageRolloutRecoverySafeSpecChange(old, reverted) {
		t.Fatal("reverting a bad sidecar must be allowed during an active rollout")
	}
	topology := reverted.DeepCopy()
	topology.Spec.Replicas++
	if v1beta1StorageRolloutRecoverySafeSpecChange(old, topology) {
		t.Fatal("topology changes stay frozen")
	}

	oldNode := podExtrasNode()
	oldNode.UID = "uid"
	oldNode.Spec.ExtraContainers = podExtraContainers(t, `{"name":"bad","image":"does-not-exist"}`)
	newNode := oldNode.DeepCopy()
	newNode.Spec.ExtraContainers = nil
	cluster := &v1beta2.GarageCluster{Status: v1beta2.GarageClusterStatus{StorageRollout: &v1beta2.StorageRolloutStatus{
		GarageNodeName: oldNode.Name, GarageNodeUID: "uid",
	}}}
	if !garageNodeStorageRolloutRecoveryAllowed(oldNode, newNode, cluster, true, false) {
		t.Fatal("reverting a node-level bad sidecar must be allowed during an active rollout")
	}
	newNode.Spec.Zone = "other"
	if garageNodeStorageRolloutRecoveryAllowed(oldNode, newNode, cluster, true, false) {
		t.Fatal("non-workload node changes stay frozen")
	}
}

func podExtrasNode() *GarageNode {
	return &GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a", Namespace: testWebhookNS},
		Spec: GarageNodeSpec{
			ClusterRef: ClusterReference{Name: "extras"},
			Zone:       testZone,
			Capacity:   ptrQuantity(resource.MustParse("100Gi")),
			Storage: &NodeStorageConfig{
				Metadata: &NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
				Data:     &NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
			},
		},
	}
}

func TestGarageNodeValidatesPodExtrasStatically(t *testing.T) {
	valid := podExtrasNode()
	valid.Spec.ExtraContainers = podExtraContainers(t, extrasSidecarJSON)
	valid.Spec.ExtraVolumes = podExtraVolumes(t, extrasVolumeJSON)
	if err := valid.validatePodExtras(); err != nil {
		t.Fatalf("valid node extras rejected: %v", err)
	}
	if _, err := valid.validateGarageNode(); err != nil {
		t.Fatalf("valid node extras rejected by node validation: %v", err)
	}

	// A node that inherits the tier's volumes may mount names it does not
	// declare: that part is checked against the cluster.
	inherits := podExtrasNode()
	inherits.Spec.ExtraContainers = podExtraContainers(t, extrasSidecarJSON)
	if err := inherits.validatePodExtras(); err != nil {
		t.Fatalf("node inheriting volumes rejected statically: %v", err)
	}

	cases := map[string]struct {
		mutate func(*GarageNode)
		want   string
	}{
		"unknown field": {func(n *GarageNode) { n.Spec.ExtraContainers = podExtraContainers(t, extrasTypoJSON) }, "volumeMount"},
		"metadata mount, even when volumes are inherited": {func(n *GarageNode) {
			n.Spec.ExtraContainers = podExtraContainers(t, extrasBadMountJSON)
		}, "node_key"},
		"undeclared mount when the node declares its own volumes": {func(n *GarageNode) {
			n.Spec.ExtraVolumes = podExtraVolumes(t, `{"name":"other","emptyDir":{}}`)
			n.Spec.ExtraContainers = podExtraContainers(t, extrasSidecarJSON)
		}, "ddns-state"},
		"external node": {func(n *GarageNode) {
			n.Spec.External = &ExternalNodeConfig{Address: "10.0.0.2", Port: 3901}
			n.Spec.ExtraContainers = podExtraContainers(t, extrasSidecarJSON)
		}, "external GarageNode"},
		"node-local-pool-backed node": {func(n *GarageNode) {
			n.Spec.Backing = NodeBackingNodeLocalPool
			n.Spec.ExtraContainers = podExtraContainers(t, extrasSidecarJSON)
		}, "node-local-pool"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			node := podExtrasNode()
			tc.mutate(node)
			if err := node.validatePodExtras(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validatePodExtras = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestGarageNodeEffectivePodExtrasOverrideSemantics(t *testing.T) {
	tier := &v1beta2.PodTemplate{
		InitContainers:  podExtraContainers(t, extrasGatewayJSON),
		ExtraContainers: podExtraContainers(t, extrasSidecarJSON),
		ExtraVolumes:    podExtraVolumes(t, extrasVolumeJSON),
	}
	node := podExtrasNode()
	in := node.EffectivePodExtras(tier)
	if len(in.InitContainers) != 1 || len(in.ExtraContainers) != 1 || len(in.ExtraVolumes) != 1 {
		t.Fatalf("a node with no lists must inherit all three: %#v", in)
	}
	node.Spec.ExtraContainers = []v1beta2.PodExtraContainer{}
	in = node.EffectivePodExtras(tier)
	if len(in.ExtraContainers) != 0 || len(in.InitContainers) != 1 || len(in.ExtraVolumes) != 1 {
		t.Fatalf("an explicit empty list opts out of that list only: %#v", in)
	}
	node.Spec.ExtraContainers = podExtraContainers(t, `{"name":"mine","image":"a"}`)
	in = node.EffectivePodExtras(tier)
	if len(in.ExtraContainers) != 1 || in.ExtraContainers[0].Name != "mine" {
		t.Fatalf("a non-empty node list replaces the tier's list: %#v", in)
	}
	if got := node.EffectivePodExtras(nil); len(got.InitContainers) != 0 || len(got.ExtraContainers) != 1 {
		t.Fatalf("a nil tier yields only the node's lists: %#v", got)
	}
}

func TestGarageNodeValidatorChecksMergedExtrasAgainstCluster(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1beta2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cluster := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "extras", Namespace: testWebhookNS},
		Spec: v1beta2.GarageClusterSpec{Storage: &v1beta2.StorageSpec{
			Replicas: 1,
			PodTemplate: v1beta2.PodTemplate{
				ExtraVolumes: podExtraVolumes(t, extrasVolumeJSON),
			},
		}},
	}
	validator := &GarageNodeValidator{apiReader: fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster).Build()}
	ctx := context.Background()

	node := podExtrasNode()
	node.Spec.ExtraContainers = podExtraContainers(t, extrasSidecarJSON)
	if err := validator.validatePodExtrasAgainstCluster(ctx, node); err != nil {
		t.Fatalf("a mount of a tier-declared volume must resolve through the merge: %v", err)
	}

	node.Spec.ExtraContainers = podExtraContainers(t, `{"name":"x","image":"a","volumeMounts":[{"name":"nope","mountPath":"/n"}]}`)
	if err := validator.validatePodExtrasAgainstCluster(ctx, node); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("a mount of a volume nobody declares must be rejected: %v", err)
	}

	node.Spec.ExtraContainers = podExtraContainers(t, `{"name":"x","image":"a","ports":[{"containerPort":3900}]}`)
	if err := validator.validatePodExtrasAgainstCluster(ctx, node); err == nil || !strings.Contains(err.Error(), "S3 API") {
		t.Fatalf("a port that collides with a Garage listener must be rejected: %v", err)
	}

	// A missing cluster is not this webhook's problem; the controller re-checks.
	missing := podExtrasNode()
	missing.Spec.ClusterRef.Name = "absent"
	missing.Spec.ExtraContainers = podExtraContainers(t, extrasSidecarJSON)
	if err := validator.validatePodExtrasAgainstCluster(ctx, missing); err != nil {
		t.Fatalf("missing cluster must not fail validation: %v", err)
	}
}

// Regression: equality.Semantic.DeepEqual panics on unexported fields, so an
// update where old and new both carry extras was denied with a panic.
func TestV1Beta1UpdateWithExtrasOnBothObjectsDoesNotPanic(t *testing.T) {
	ctx := context.Background()

	old := podExtrasSpoke()
	old.Spec.InitContainers = podExtraContainers(t, extrasInitJSON)
	old.Spec.ExtraContainers = podExtraContainers(t, extrasSidecarJSON)
	old.Spec.ExtraVolumes = podExtraVolumes(t, extrasVolumeJSON)
	touched := old.DeepCopy()
	touched.Labels = map[string]string{"touched": "true"}
	validator := &GarageClusterValidator{}
	if _, err := validator.ValidateUpdate(ctx, old, touched); err != nil {
		t.Fatalf("unrelated cluster update with extras rejected: %v", err)
	}
	edited := old.DeepCopy()
	edited.Spec.ExtraContainers = podExtraContainers(t, `{"name":"ddns","image":"busybox:1.38"}`)
	edited.Spec.ExtraVolumes = old.Spec.ExtraVolumes
	if _, err := validator.ValidateUpdate(ctx, old, edited); err != nil {
		t.Fatalf("editing an extra on a cluster rejected: %v", err)
	}

	oldNode := podExtrasNode()
	oldNode.Spec.ExtraContainers = podExtraContainers(t, extrasSidecarJSON)
	oldNode.Spec.ExtraVolumes = podExtraVolumes(t, extrasVolumeJSON)
	nodeValidator := &GarageNodeValidator{}
	touchedNode := oldNode.DeepCopy()
	touchedNode.Labels = map[string]string{"touched": "true"}
	if _, err := nodeValidator.ValidateUpdate(ctx, oldNode, touchedNode); err != nil {
		t.Fatalf("unrelated node update with extras rejected: %v", err)
	}
	editedNode := oldNode.DeepCopy()
	editedNode.Spec.ExtraContainers = podExtraContainers(t, `{"name":"ddns","image":"busybox:1.38"}`)
	if _, err := nodeValidator.ValidateUpdate(ctx, oldNode, editedNode); err != nil {
		t.Fatalf("editing an extra on a node rejected: %v", err)
	}
}
