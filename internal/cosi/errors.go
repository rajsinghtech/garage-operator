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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// MapGarageErrorToCOSI converts a Garage API error to a gRPC status error
func MapGarageErrorToCOSI(err error) error {
	if err == nil {
		return nil
	}

	// Check for bucket not empty first (more specific)
	if garage.IsBucketNotEmpty(err) {
		return status.Errorf(codes.FailedPrecondition, "bucket is not empty: %v", err)
	}

	if garage.IsNotFound(err) {
		return status.Errorf(codes.NotFound, "resource not found: %v", err)
	}

	if garage.IsConflict(err) {
		return status.Errorf(codes.AlreadyExists, "resource already exists: %v", err)
	}

	if garage.IsBadRequest(err) {
		return status.Errorf(codes.InvalidArgument, "invalid argument: %v", err)
	}

	// Default to Unavailable for other errors (will be retried)
	return status.Errorf(codes.Unavailable, "service unavailable: %v", err)
}

// ErrUnsupportedAuthType is returned when SERVICE_ACCOUNT auth is requested
var ErrUnsupportedAuthType = status.Error(codes.InvalidArgument, "only KEY authentication is supported, SERVICE_ACCOUNT is not available")

// ErrUnsupportedProtocol is returned when a non-S3 protocol is requested
var ErrUnsupportedProtocol = status.Error(codes.InvalidArgument, "only S3 protocol is supported")

// ErrClusterNotFound is returned when the referenced GarageCluster doesn't exist
func ErrClusterNotFound(name, namespace string) error {
	return status.Errorf(codes.InvalidArgument, "GarageCluster %s/%s not found", namespace, name)
}

// ErrClusterNotReady is returned when the GarageCluster is not ready
func ErrClusterNotReady(name, namespace string) error {
	return status.Errorf(codes.Unavailable, "GarageCluster %s/%s is not ready", namespace, name)
}
