/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta1

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
)

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
