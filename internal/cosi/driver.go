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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/grpc"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cosiproto "sigs.k8s.io/container-object-storage-interface/proto"
)

var driverLog = ctrl.Log.WithName("cosi-driver")

const (
	protoUnix = "unix"
	protoTCP  = "tcp"
)

// DriverConfig holds configuration for the COSI driver
type DriverConfig struct {
	// DriverName is the name of the driver (e.g., "garage.rajsingh.info")
	DriverName string
	// Endpoint is the COSI socket path (e.g., "unix:///var/lib/cosi/cosi.sock")
	Endpoint string
	// Namespace is where shadow resources are created
	Namespace string
}

// Driver is the main COSI driver server
type Driver struct {
	config            DriverConfig
	client            client.Client
	grpcServer        *grpc.Server
	identityServer    *IdentityServer
	provisionerServer *ProvisionerServer
}

// NewDriver creates a new COSI driver
func NewDriver(cfg DriverConfig, c client.Client) *Driver {
	return &Driver{
		config:            cfg,
		client:            c,
		identityServer:    NewIdentityServer(cfg.DriverName),
		provisionerServer: NewProvisionerServer(c, cfg.Namespace),
	}
}

// Run starts the COSI gRPC server
func (d *Driver) Run(ctx context.Context) error {
	// Parse the endpoint
	proto, addr := parseEndpoint(d.config.Endpoint)

	// For Unix sockets, remove existing socket file
	if proto == protoUnix {
		if err := os.Remove(addr); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove existing socket: %w", err)
		}
		// Ensure directory exists with restricted permissions
		if err := os.MkdirAll(filepath.Dir(addr), 0750); err != nil {
			return fmt.Errorf("failed to create socket directory: %w", err)
		}
	}

	// Create listener
	listener, err := net.Listen(proto, addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	// Create gRPC server
	d.grpcServer = grpc.NewServer()
	cosiproto.RegisterIdentityServer(d.grpcServer, d.identityServer)
	cosiproto.RegisterProvisionerServer(d.grpcServer, d.provisionerServer)

	driverLog.Info("Starting COSI driver", "endpoint", d.config.Endpoint, "driver", d.config.DriverName)

	// Handle context cancellation
	go func() {
		<-ctx.Done()
		driverLog.Info("Shutting down COSI driver")
		d.grpcServer.GracefulStop()
	}()

	// Start serving
	if err := d.grpcServer.Serve(listener); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}

	return nil
}

// parseEndpoint parses a COSI endpoint string (e.g., "unix:///var/lib/cosi/cosi.sock")
func parseEndpoint(endpoint string) (string, string) {
	if addr, found := strings.CutPrefix(endpoint, "unix://"); found {
		return protoUnix, addr
	}
	if addr, found := strings.CutPrefix(endpoint, "tcp://"); found {
		return protoTCP, addr
	}
	// Default to unix socket
	return protoUnix, endpoint
}
