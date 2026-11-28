/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta2

import "testing"

// Garage v3 is not wire- or Admin-API-compatible with v2; a GarageCluster
// tagged with it must get an admission warning, but is not rejected.
func TestUnsupportedGarageMajorWarning(t *testing.T) {
	for _, tc := range []struct {
		image string
		want  int
	}{
		{"dxflrs/garage:v3.0.0-beta1", 1},
		{"dxflrs/garage:v2.6.0", 0},
		{"", 0},
	} {
		cluster := discoveryTestCluster(tc.image, nil)
		warnings, err := cluster.validateGarageCluster()
		if err != nil {
			t.Fatalf("%q: an unsupported major must warn, not reject: %v", tc.image, err)
		}
		if got := warningsContaining(warnings, "does not support yet"); got != tc.want {
			t.Errorf("%q: unsupported-major warnings = %d, want %d: %v", tc.image, got, tc.want, warnings)
		}
	}
}
