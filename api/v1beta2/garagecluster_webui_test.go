/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta2

import "testing"

const webUIOldReleaseWarning = "the web admin UI is served only by Garage v2.6.0"

func TestWebUIAdmissionWarnings(t *testing.T) {
	for _, tc := range []struct {
		name  string
		image string
		webUI bool
		want  int
	}{
		{"old release with webUI", "dxflrs/garage:v2.5.0", true, 1},
		{"old release without webUI", "dxflrs/garage:v2.5.0", false, 0},
		{"v2.6.0 with webUI", "dxflrs/garage:v2.6.0", true, 0},
		{"digest-only image is left to WebUIAvailable", "dxflrs/garage@sha256:4b5a318fc9fe2fbec5d3af590eeafe05d83492e6411266fa0b9e215c20264013", true, 0},
		{"unset image uses the operator default", "", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cluster := discoveryTestCluster(tc.image, nil)
			if tc.webUI {
				cluster.Spec.Admin = &AdminConfig{WebUI: &WebUIConfig{
					Hostname: "garage-ui.example.com",
					Ingress:  &WebUIIngressConfig{},
				}}
			}
			warnings, err := cluster.validateGarageCluster()
			if err != nil {
				t.Fatalf("webUI warnings must never reject the object: %v", err)
			}
			if got := warningsContaining(warnings, webUIOldReleaseWarning); got != tc.want {
				t.Errorf("webUI warnings = %d, want %d: %v", got, tc.want, warnings)
			}
		})
	}
}
