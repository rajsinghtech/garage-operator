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
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/rajsinghtech/garage-operator/internal/garage"
)

func TestMapGarageErrorToCOSI(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode codes.Code
	}{
		{
			name:     "not found",
			err:      &garage.APIError{StatusCode: 404, Message: "not found"},
			wantCode: codes.NotFound,
		},
		{
			name:     "conflict",
			err:      &garage.APIError{StatusCode: 409, Message: "conflict"},
			wantCode: codes.AlreadyExists,
		},
		{
			name:     "bucket not empty",
			err:      &garage.APIError{StatusCode: 409, Message: "BucketNotEmpty"},
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "bad request",
			err:      &garage.APIError{StatusCode: 400, Message: "bad request"},
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "server error",
			err:      &garage.APIError{StatusCode: 500, Message: "internal error"},
			wantCode: codes.Unavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grpcErr := MapGarageErrorToCOSI(tt.err)
			st, ok := status.FromError(grpcErr)
			assert.True(t, ok)
			assert.Equal(t, tt.wantCode, st.Code())
		})
	}
}
