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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// spec.admin.webUI is enforced by the generated CRD schema (pattern, enum,
// CEL) with no admission webhook in front of it. The CRDs only install when
// every CEL rule fits the cost budget, so these specs also prove the rules are
// cheap enough to ship.
var _ = Describe("spec.admin.webUI CRD schema", func() {
	const ns = testNamespace
	var seq int
	uniq := func(prefix string) string {
		seq++
		return fmt.Sprintf("%s-%d", prefix, seq)
	}
	qty := func(v string) *resource.Quantity { q := resource.MustParse(v); return &q }
	cleanup := func(obj client.Object) {
		DeferCleanup(func() {
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj); err == nil {
				obj.SetFinalizers(nil)
				_ = k8sClient.Update(ctx, obj)
				_ = k8sClient.Delete(ctx, obj)
			}
		})
	}
	ingress := func() *garagev1beta2.WebUIConfig {
		return &garagev1beta2.WebUIConfig{
			Hostname: "garage-ui.example.com",
			Ingress:  &garagev1beta2.WebUIIngressConfig{IngressClassName: "nginx", TLSSecretName: "garage-ui-tls"},
		}
	}
	gateway := func() *garagev1beta2.WebUIGatewayConfig {
		return &garagev1beta2.WebUIGatewayConfig{ParentRefs: []gatewayv1.ParentReference{{Name: "public"}}}
	}
	cluster := func(webUI *garagev1beta2.WebUIConfig) *garagev1beta2.GarageCluster {
		return &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: uniq("webui-schema"), Namespace: ns},
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{Size: qty("1Gi")},
					Data:     &garagev1beta2.VolumeConfig{Size: qty("10Gi")},
				},
				Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
				Admin:       &garagev1beta2.AdminConfig{WebUI: webUI},
			},
		}
	}
	expectInvalid := func(obj client.Object, want string) {
		GinkgoHelper()
		err := k8sClient.Create(ctx, obj)
		Expect(err).To(HaveOccurred())
		Expect(errors.IsInvalid(err)).To(BeTrue(), "got %v", err)
		Expect(err.Error()).To(ContainSubstring(want))
	}

	It("accepts an Ingress exposure and an HTTPRoute exposure", func() {
		c := cluster(ingress())
		Expect(k8sClient.Create(ctx, c)).To(Succeed())
		cleanup(c)
		stored := &garagev1beta2.GarageCluster{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(c), stored)).To(Succeed())
		Expect(stored.Spec.Admin.WebUI.Ingress.TLSSecretName).To(Equal("garage-ui-tls"))

		g := cluster(&garagev1beta2.WebUIConfig{Hostname: "ui.garage.example.com", Scheme: "https", Gateway: gateway()})
		Expect(k8sClient.Create(ctx, g)).To(Succeed())
		cleanup(g)
	})

	It("accepts the field on an edge gateway (connectTo plus gateway)", func() {
		c := cluster(ingress())
		c.Spec.Storage = nil
		c.Spec.Gateway = &garagev1beta2.GatewaySpec{Replicas: 1}
		c.Spec.ConnectTo = &garagev1beta2.ConnectToConfig{AdminAPIEndpoint: "http://storage.example.net:3903"}
		Expect(k8sClient.Create(ctx, c)).To(Succeed())
		cleanup(c)
	})

	It("requires exactly one of ingress and gateway", func() {
		both := ingress()
		both.Gateway = gateway()
		expectInvalid(cluster(both), "exactly one of webUI.ingress or webUI.gateway must be set")
		expectInvalid(cluster(&garagev1beta2.WebUIConfig{Hostname: "garage-ui.example.com"}),
			"exactly one of webUI.ingress or webUI.gateway must be set")
	})

	DescribeTable("rejects invalid hostnames",
		func(host string) {
			cfg := ingress()
			cfg.Hostname = host
			expectInvalid(cluster(cfg), "hostname")
		},
		Entry("wildcard", "*.example.com"),
		Entry("scheme", "https://garage-ui.example.com"),
		Entry("path", "garage-ui.example.com/ui"),
		Entry("trailing dot", "garage-ui.example.com."),
	)

	It("rejects a hostname-less exposure and an unknown scheme", func() {
		cfg := ingress()
		cfg.Hostname = ""
		expectInvalid(cluster(cfg), "hostname")
		cfg = ingress()
		cfg.Scheme = "ftp"
		expectInvalid(cluster(cfg), "scheme")
	})

	It("rejects an empty parentRefs list", func() {
		expectInvalid(cluster(&garagev1beta2.WebUIConfig{
			Hostname: "garage-ui.example.com",
			Gateway:  &garagev1beta2.WebUIGatewayConfig{ParentRefs: []gatewayv1.ParentReference{}},
		}), "parentRefs")
	})

	It("rejects webUI on a management handle", func() {
		c := cluster(ingress())
		c.Spec.Storage = nil
		c.Spec.ConnectTo = &garagev1beta2.ConnectToConfig{AdminAPIEndpoint: "http://storage.example.net:3903"}
		expectInvalid(c, "spec.admin.webUI requires a Garage workload")
	})

	It("enforces the same schema on the v1beta1 GarageCluster", func() {
		legacy := &legacyGarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: uniq("webui-legacy"), Namespace: ns},
			Spec: garagev1beta1.GarageClusterSpec{
				Replicas: 1,
				Admin: &garagev1beta1.AdminConfig{WebUI: &garagev1beta1.WebUIConfig{
					Hostname: "garage-ui.example.com",
					Ingress:  &garagev1beta1.WebUIIngressConfig{},
					Gateway:  &garagev1beta1.WebUIGatewayConfig{ParentRefs: []gatewayv1.ParentReference{{Name: "public"}}},
				}},
			},
		}
		expectInvalid(legacy, "exactly one of webUI.ingress or webUI.gateway must be set")
	})
})
