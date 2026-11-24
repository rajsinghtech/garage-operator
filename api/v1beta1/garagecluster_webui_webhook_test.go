/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta1

import "testing"

func TestWebUIAdmissionWarningsV1Beta1(t *testing.T) {
	cluster := discoveryTestCluster("dxflrs/garage:v2.5.0", nil)
	cluster.Spec.Admin = &AdminConfig{WebUI: &WebUIConfig{Hostname: "garage-ui.example.com", Ingress: &WebUIIngressConfig{}}}
	warnings, err := cluster.validateGarageCluster()
	if err != nil {
		t.Fatalf("webUI warnings must never reject the object: %v", err)
	}
	if got := warningsContaining(warnings, "the web admin UI is served only by Garage v2.6.0"); got != 1 {
		t.Fatalf("webUI warnings = %d, want 1: %v", got, warnings)
	}
	cluster.Spec.Image = "dxflrs/garage:v2.6.0"
	warnings, _ = cluster.validateGarageCluster()
	if got := warningsContaining(warnings, "web admin UI"); got != 0 {
		t.Fatalf("no warning expected on v2.6.0: %v", warnings)
	}
}
