/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta1

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// spec.admin.webUI and status.endpoints.webUI are copied as JSON between the
// versions, so a field missing from either side would be dropped silently on
// every v1beta1 read or write.
func TestConvert_WebUIRoundTrip(t *testing.T) {
	section := gatewayv1.SectionName("https")
	for _, webUI := range []*WebUIConfig{
		{
			Hostname: "garage-ui.example.com",
			Scheme:   "https",
			Ingress: &WebUIIngressConfig{
				IngressClassName: "nginx",
				TLSSecretName:    "garage-ui-tls",
				Labels:           map[string]string{"team": "storage"},
				Annotations:      map[string]string{"cert-manager.io/cluster-issuer": "letsencrypt"},
			},
		},
		{
			Hostname: "garage-ui.example.com",
			Gateway: &WebUIGatewayConfig{
				ParentRefs:  []gatewayv1.ParentReference{{Name: "public", SectionName: &section}},
				Labels:      map[string]string{"team": "storage"},
				Annotations: map[string]string{"external-dns.alpha.kubernetes.io/ttl": "60"},
			},
		},
	} {
		src := &GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: testStoreCR, Namespace: testNS},
			Spec: GarageClusterSpec{
				Replicas: 3,
				Admin:    &AdminConfig{BindPort: 3903, WebUI: webUI},
			},
			Status: GarageClusterStatus{
				Endpoints: &ClusterEndpoints{
					Admin: "garage.ns.svc.cluster.local:3903",
					WebUI: &WebUIEndpoints{
						InCluster: "http://garage.ns.svc.cluster.local:3903/ui/",
						External:  "https://garage-ui.example.com/ui/",
					},
				},
			},
		}
		hub := &v1beta2.GarageCluster{}
		if err := src.ConvertTo(hub); err != nil {
			t.Fatalf("ConvertTo: %v", err)
		}
		if hub.Spec.Admin == nil || hub.Spec.Admin.WebUI == nil || hub.Spec.Admin.WebUI.Hostname != webUI.Hostname {
			t.Fatalf("hub spec.admin.webUI = %+v", hub.Spec.Admin)
		}
		if hub.Status.Endpoints == nil || hub.Status.Endpoints.WebUI == nil ||
			hub.Status.Endpoints.WebUI.External != "https://garage-ui.example.com/ui/" {
			t.Fatalf("hub status.endpoints.webUI = %+v", hub.Status.Endpoints)
		}
		back := &GarageCluster{}
		if err := back.ConvertFrom(hub); err != nil {
			t.Fatalf("ConvertFrom: %v", err)
		}
		if !equality.Semantic.DeepEqual(back.Spec.Admin, src.Spec.Admin) {
			t.Fatalf("spec.admin round trip:\n got %+v\nwant %+v", back.Spec.Admin, src.Spec.Admin)
		}
		if !equality.Semantic.DeepEqual(back.Status.Endpoints, src.Status.Endpoints) {
			t.Fatalf("status.endpoints round trip:\n got %+v\nwant %+v", back.Status.Endpoints, src.Status.Endpoints)
		}
	}
}
