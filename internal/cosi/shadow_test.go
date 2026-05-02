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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestShadowResourceName(t *testing.T) {
	tests := []struct {
		cosiName string
	}{
		{testMyBucket},
		{"default-my-bucket"},
		{"my-very-long-bucket-name-that-exceeds-normal-limits"},
	}

	for _, tt := range tests {
		t.Run(tt.cosiName, func(t *testing.T) {
			got := ShadowResourceName(tt.cosiName)
			// Should start with "cosi-" prefix
			assert.True(t, strings.HasPrefix(got, "cosi-"), "should have cosi- prefix")
			// Should be 63 chars or less (K8s limit)
			assert.LessOrEqual(t, len(got), 63, "should be <= 63 chars")
			// Same input should always produce same output
			assert.Equal(t, got, ShadowResourceName(tt.cosiName), "should be deterministic")
		})
	}

	// Different inputs should produce different outputs
	name1 := ShadowResourceName("bucket-a")
	name2 := ShadowResourceName("bucket-b")
	assert.NotEqual(t, name1, name2, "different inputs should produce different names")
}

func TestShadowResourceLabels(t *testing.T) {
	t.Run("bucket labels", func(t *testing.T) {
		labels := ShadowBucketLabels("my-bucket-claim")

		assert.Equal(t, "true", labels[LabelCOSIManaged])
		assert.Equal(t, "my-bucket-claim", labels[LabelCOSIBucketClaim])
	})

	t.Run("key labels", func(t *testing.T) {
		labels := ShadowKeyLabels("my-bucket-access")

		assert.Equal(t, "true", labels[LabelCOSIManaged])
		assert.Equal(t, "my-bucket-access", labels[LabelCOSIBucketAccess])
	})
}

func TestCreateShadowKeyWithID_StoresServiceAccountName(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	mgr := NewShadowManager(fakeClient, "garage-system")

	key, err := mgr.CreateShadowKeyWithID(context.Background(), "my-access", "GKabc", "my-cluster", "garage-system",
		[]BucketPermission{{BucketID: testBucket1, Read: true, Write: true}},
		"my-serviceaccount",
	)
	require.NoError(t, err)
	assert.Equal(t, "my-serviceaccount", key.Annotations[AnnotationCOSIServiceAccountName])
}
