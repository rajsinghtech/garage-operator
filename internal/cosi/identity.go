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

	cosiproto "sigs.k8s.io/container-object-storage-interface/proto"
)

// IdentityServer implements the COSI Identity service
type IdentityServer struct {
	cosiproto.UnimplementedIdentityServer
	driverName string
}

// NewIdentityServer creates a new IdentityServer
func NewIdentityServer(driverName string) *IdentityServer {
	return &IdentityServer{
		driverName: driverName,
	}
}

// DriverGetInfo returns information about the COSI driver
func (s *IdentityServer) DriverGetInfo(ctx context.Context, req *cosiproto.DriverGetInfoRequest) (*cosiproto.DriverGetInfoResponse, error) {
	return &cosiproto.DriverGetInfoResponse{
		Name: s.driverName,
		SupportedProtocols: []*cosiproto.ObjectProtocol{
			{
				Type: cosiproto.ObjectProtocol_S3,
			},
		},
	}, nil
}
