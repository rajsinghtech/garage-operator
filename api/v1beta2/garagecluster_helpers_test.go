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

package v1beta2

import "testing"

func TestIsManagementHandle(t *testing.T) {
	tests := []struct {
		name string
		spec GarageClusterSpec
		want bool
	}{
		{
			name: "connectTo only",
			spec: GarageClusterSpec{ConnectTo: &ConnectToConfig{AdminAPIEndpoint: "http://x:3903"}},
			want: true,
		},
		{
			name: "connectTo + storage (edge/unified, not a handle)",
			spec: GarageClusterSpec{Storage: &StorageSpec{}, ConnectTo: &ConnectToConfig{}},
			want: false,
		},
		{
			name: "connectTo + gateway (edge gateway, not a handle)",
			spec: GarageClusterSpec{Gateway: &GatewaySpec{}, ConnectTo: &ConnectToConfig{}},
			want: false,
		},
		{
			name: "storage only",
			spec: GarageClusterSpec{Storage: &StorageSpec{}},
			want: false,
		},
		{
			name: "no connectTo",
			spec: GarageClusterSpec{},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &GarageCluster{Spec: tt.spec}
			if got := g.IsManagementHandle(); got != tt.want {
				t.Errorf("IsManagementHandle() = %v, want %v", got, tt.want)
			}
		})
	}
}
