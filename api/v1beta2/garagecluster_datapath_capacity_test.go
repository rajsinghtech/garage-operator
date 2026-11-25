/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta2

import (
	"strings"
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

func TestValidateCreateRejectsWritableDataPathWithoutCapacity(t *testing.T) {
	cluster := dataPathCapacityAdmissionCluster(DataPath{Path: "/d"})
	warnings, err := (&GarageClusterValidator{}).ValidateCreate(t.Context(), cluster)
	if err == nil || !strings.Contains(err.Error(), "Garage refuses to start") || !strings.Contains(err.Error(), "spec.storage.data.paths[0]") {
		t.Fatalf("create err = %v, warnings = %v, want a reject naming the path and Garage refusing to start", err, warnings)
	}
}

func TestValidateCreateAcceptsWritableDataPathWithCapacity(t *testing.T) {
	q := resource.MustParse("1Ti")
	cluster := dataPathCapacityAdmissionCluster(DataPath{Path: "/d", Capacity: &q})
	if _, err := (&GarageClusterValidator{}).ValidateCreate(t.Context(), cluster); err != nil {
		t.Fatalf("create with capacity rejected: %v", err)
	}
}

func TestValidateUpdateWarnsWritableDataPathWithoutCapacity(t *testing.T) {
	oldCluster := dataPathCapacityAdmissionCluster(DataPath{Path: "/d"})
	newCluster := oldCluster.DeepCopy()
	newCluster.Labels = map[string]string{"touch": "1"}
	warnings, err := (&GarageClusterValidator{}).ValidateUpdate(t.Context(), oldCluster, newCluster)
	if err != nil {
		t.Fatalf("update of an existing object must not be rejected: %v", err)
	}
	if got := warningsContaining(warnings, "Garage refuses to start"); got != 1 {
		t.Fatalf("update warnings = %v, want one capacity warning", warnings)
	}
}

func dataPathCapacityAdmissionCluster(path DataPath) *GarageCluster {
	cluster := discoveryTestCluster("", nil)
	cluster.Spec.Storage.Data = &VolumeConfig{Paths: []DataPath{path}}
	return cluster
}
