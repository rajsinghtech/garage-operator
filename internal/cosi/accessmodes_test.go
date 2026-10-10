/*
Copyright 2026.

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

package cosi

import (
	"testing"

	cosiv1alpha2 "sigs.k8s.io/container-object-storage-interface/client/apis/objectstorage/v1alpha2"
)

func TestMapAccessModesFromAPI(t *testing.T) {
	const (
		rw = cosiv1alpha2.BucketAccessModeReadWrite
		ro = cosiv1alpha2.BucketAccessModeReadOnly
		wo = cosiv1alpha2.BucketAccessModeWriteOnly
	)
	cases := []struct {
		name string
		in   cosiv1alpha2.BucketAccessModes
		want AccessMode
	}{
		{"both unset keeps the ReadWrite default", cosiv1alpha2.BucketAccessModes{}, AccessModeReadWrite},
		{"objectData ReadWrite", cosiv1alpha2.BucketAccessModes{ObjectData: rw}, AccessModeReadWrite},
		{"objectData ReadOnly", cosiv1alpha2.BucketAccessModes{ObjectData: ro}, AccessModeReadOnly},
		{"objectData WriteOnly", cosiv1alpha2.BucketAccessModes{ObjectData: wo}, AccessModeWriteOnly},
		{"objectMetadata alone ReadOnly", cosiv1alpha2.BucketAccessModes{ObjectMetadata: ro}, AccessModeReadOnly},
		{"read data + write metadata unions to ReadWrite", cosiv1alpha2.BucketAccessModes{ObjectData: ro, ObjectMetadata: wo}, AccessModeReadWrite},
		{"both ReadOnly", cosiv1alpha2.BucketAccessModes{ObjectData: ro, ObjectMetadata: ro}, AccessModeReadOnly},
		{"bucketMetadata alone does not widen the default", cosiv1alpha2.BucketAccessModes{BucketMetadata: ro}, AccessModeReadWrite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapAccessModesFromAPI(tc.in); got != tc.want {
				t.Fatalf("mapAccessModesFromAPI(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
