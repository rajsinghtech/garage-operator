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

package cosi

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cosiproto "sigs.k8s.io/container-object-storage-interface/proto"
)

func TestIdentityServer_DriverGetInfo(t *testing.T) {
	server := NewIdentityServer("garage.rajsingh.info")

	resp, err := server.DriverGetInfo(context.Background(), &cosiproto.DriverGetInfoRequest{})

	require.NoError(t, err)
	assert.Equal(t, "garage.rajsingh.info", resp.Name)
}
