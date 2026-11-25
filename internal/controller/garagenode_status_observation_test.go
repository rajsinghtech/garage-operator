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
	"slices"
	"testing"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

func TestApplyGarageNodeObservationsPopulatesAndClearsStatus(t *testing.T) {
	address := "10.0.0.8:3901"
	hostname := "garage-0"
	version := "v2.2.0"
	partitions := uint64(17)
	status := garagev1beta1.GarageNodeStatus{}
	applyGarageNodeObservations(&status, &garage.NodeInfo{
		Address:           &address,
		Hostname:          &hostname,
		GarageVersion:     &version,
		DataPartition:     &garage.FreeSpaceResp{Available: 25, Total: 100},
		MetadataPartition: &garage.FreeSpaceResp{Available: 0, Total: 0},
	}, &garage.LayoutRole{Tags: []string{"rack:a"}, StoredPartitions: &partitions})

	if status.Address != address || status.Hostname != hostname || status.Version != version ||
		len(status.Tags) != 1 || status.Tags[0] != "rack:a" || status.Partitions != 17 {
		t.Fatalf("observations not populated: %+v", status)
	}
	if status.DataPartition == nil || status.DataPartition.UsedPercent != 75 ||
		status.DataPartition.Available == nil || status.DataPartition.Available.Value() != 25 ||
		status.DataPartition.Total == nil || status.DataPartition.Total.Value() != 100 {
		t.Fatalf("data partition not populated: %+v", status.DataPartition)
	}
	if status.MetadataPartition == nil || status.MetadataPartition.UsedPercent != 0 {
		t.Fatalf("zero-total metadata partition is not zero-safe: %+v", status.MetadataPartition)
	}

	applyGarageNodeBuildInfo(&status, &garage.NodeBuildInfo{DBEngine: "lmdb", GarageFeatures: []string{"k2v", "webadmin"}})
	if status.DBEngine != "lmdb" || !slices.Equal(status.GarageFeatures, []string{"k2v", "webadmin"}) {
		t.Fatalf("build info not populated: dbEngine=%q features=%v", status.DBEngine, status.GarageFeatures)
	}

	applyGarageNodeObservations(&status, nil, nil)
	if status.DBEngine != "" || status.GarageFeatures != nil {
		t.Fatalf("stale build info not cleared: dbEngine=%q features=%v", status.DBEngine, status.GarageFeatures)
	}
	if status.Address != "" || status.Hostname != "" || status.Version != "" || status.Tags != nil ||
		status.DataPartition != nil || status.MetadataPartition != nil || status.Partitions != 0 {
		t.Fatalf("stale observations not cleared: %+v", status)
	}
}
