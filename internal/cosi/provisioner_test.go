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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
	cosiproto "sigs.k8s.io/container-object-storage-interface/proto"
)

func TestProvisionerServer_DriverCreateBucket_MissingClusterRef(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = garagev1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverCreateBucketRequest{
		Name:       "test-bucket",
		Parameters: map[string]string{}, // Missing clusterRef
	}

	_, err := server.DriverCreateBucket(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestProvisionerServer_DriverCreateBucket_ClusterNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = garagev1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverCreateBucketRequest{
		Name: "test-bucket",
		Parameters: map[string]string{
			"clusterRef":       "nonexistent",
			"clusterNamespace": "garage-system",
		},
	}

	_, err := server.DriverCreateBucket(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestProvisionerServer_DriverCreateBucket_ClusterNotReady(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = garagev1alpha1.AddToScheme(scheme)

	// Create a cluster that's not ready
	cluster := &garagev1alpha1.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-cluster",
			Namespace: "garage-system",
		},
		Spec: garagev1alpha1.GarageClusterSpec{},
		Status: garagev1alpha1.GarageClusterStatus{
			Phase: "Pending", // Not ready
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster).Build()
	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverCreateBucketRequest{
		Name: "test-bucket",
		Parameters: map[string]string{
			"clusterRef":       "my-cluster",
			"clusterNamespace": "garage-system",
		},
	}

	_, err := server.DriverCreateBucket(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

func TestProvisionerServer_DriverGrantBucketAccess_ServiceAccountRejected(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = garagev1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverGrantBucketAccessRequest{
		AccountName: "test-access",
		Buckets: []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket{
			{BucketId: "test-bucket-id"},
		},
		AuthenticationType: &cosiproto.AuthenticationType{
			Type: cosiproto.AuthenticationType_SERVICE_ACCOUNT,
		},
		Parameters: map[string]string{
			"clusterRef": "my-cluster",
		},
	}

	_, err := server.DriverGrantBucketAccess(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestProvisionerServer_DriverGrantBucketAccess_MissingClusterRef(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = garagev1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverGrantBucketAccessRequest{
		AccountName: "test-access",
		Buckets: []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket{
			{BucketId: "test-bucket-id"},
		},
		AuthenticationType: &cosiproto.AuthenticationType{
			Type: cosiproto.AuthenticationType_KEY,
		},
		Parameters: map[string]string{}, // Missing clusterRef
	}

	_, err := server.DriverGrantBucketAccess(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestProvisionerServer_DriverGrantBucketAccess_NoBuckets(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = garagev1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	server := NewProvisionerServer(fakeClient, "garage-system")

	req := &cosiproto.DriverGrantBucketAccessRequest{
		AccountName: "test-access",
		Buckets:     []*cosiproto.DriverGrantBucketAccessRequest_AccessedBucket{}, // Empty
		AuthenticationType: &cosiproto.AuthenticationType{
			Type: cosiproto.AuthenticationType_KEY,
		},
		Parameters: map[string]string{
			"clusterRef": "my-cluster",
		},
	}

	_, err := server.DriverGrantBucketAccess(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestParseAccessMode(t *testing.T) {
	tests := []struct {
		name      string
		mode      *cosiproto.AccessMode
		wantRead  bool
		wantWrite bool
		wantOwner bool
	}{
		{
			name:      "nil mode defaults to read/write",
			mode:      nil,
			wantRead:  true,
			wantWrite: true,
			wantOwner: false,
		},
		{
			name:      "READ_WRITE",
			mode:      &cosiproto.AccessMode{Mode: cosiproto.AccessMode_READ_WRITE},
			wantRead:  true,
			wantWrite: true,
			wantOwner: false,
		},
		{
			name:      "READ_ONLY",
			mode:      &cosiproto.AccessMode{Mode: cosiproto.AccessMode_READ_ONLY},
			wantRead:  true,
			wantWrite: false,
			wantOwner: false,
		},
		{
			name:      "WRITE_ONLY",
			mode:      &cosiproto.AccessMode{Mode: cosiproto.AccessMode_WRITE_ONLY},
			wantRead:  false,
			wantWrite: true,
			wantOwner: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			read, write, owner := parseAccessMode(tt.mode)
			assert.Equal(t, tt.wantRead, read, "read mismatch")
			assert.Equal(t, tt.wantWrite, write, "write mismatch")
			assert.Equal(t, tt.wantOwner, owner, "owner mismatch")
		})
	}
}
