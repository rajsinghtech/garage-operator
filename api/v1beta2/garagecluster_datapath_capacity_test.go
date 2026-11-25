/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta2

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
)

func TestDataPathCapacityWarnings(t *testing.T) {
	q := func(s string) *resource.Quantity { v := resource.MustParse(s); return &v }
	for _, tc := range []struct {
		name string
		path DataPath
		want int
	}{
		{"capacity set", DataPath{Path: "/d", Capacity: q("1Ti")}, 0},
		{"volume size fallback", DataPath{Path: "/d", Volume: &DataPathVolumeConfig{Size: q("100Gi")}}, 0},
		{"read only needs no capacity", DataPath{Path: "/d", ReadOnly: true}, 0},
		{"no capacity and no volume", DataPath{Path: "/d"}, 1},
		{"volume without size", DataPath{Path: "/d", Volume: &DataPathVolumeConfig{}}, 1},
		{"zero capacity", DataPath{Path: "/d", Capacity: q("0")}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cluster := discoveryTestCluster("", nil)
			cluster.Spec.Storage.Data = &VolumeConfig{Paths: []DataPath{tc.path}}
			got := dataPathCapacityWarnings(cluster)
			if len(got) != tc.want {
				t.Fatalf("warnings = %v, want %d", got, tc.want)
			}
		})
	}
}
