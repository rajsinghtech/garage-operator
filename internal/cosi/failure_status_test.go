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
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cosiv1alpha2 "sigs.k8s.io/container-object-storage-interface/client/apis/objectstorage/v1alpha2"
)

func newStatusFailingCOSIClient(objects ...client.Object) (client.Client, error) {
	statusErr := errors.New("injected status update failure")
	base := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(objects...).Build()
	wrapped := interceptor.NewClient(base, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, subResourceName string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if subResourceName == "status" {
				return statusErr
			}
			return c.SubResource(subResourceName).Update(ctx, obj, opts...)
		},
	})
	return wrapped, statusErr
}

func TestBucketReconcileFailureStatusWritePreservesOriginalError(t *testing.T) {
	bucket := &cosiv1alpha2.Bucket{
		ObjectMeta: metav1.ObjectMeta{Name: "status-failure-bucket"},
		Spec: cosiv1alpha2.BucketSpec{
			DriverName:       cosiTestDriver,
			ExistingBucketID: "unsupported-static-bucket",
			Parameters:       map[string]string{paramClusterRef: "cluster"},
		},
		Status: cosiv1alpha2.BucketStatus{ReadyToUse: ptr.To(true)},
	}
	kubeClient, statusErr := newStatusFailingCOSIClient(bucket)
	reconciler := &BucketReconciler{Client: kubeClient, DriverName: cosiTestDriver}

	result, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(bucket)})

	// A non-nil, non-terminal reconcile error is what controller-runtime uses to
	// rate-limit and retry the request. Returning a zero Result with the error
	// avoids the misleading successful-reconcile path.
	require.Equal(t, reconcile.Result{}, result)
	require.Error(t, err)
	require.ErrorContains(t, err, "static provisioning not supported")
	require.ErrorIs(t, err, statusErr)
}

func TestBucketAccessFailureStatusWritePreservesOriginalError(t *testing.T) {
	access := &cosiv1alpha2.BucketAccess{
		ObjectMeta: metav1.ObjectMeta{Name: "status-failure-access", Namespace: "tenant"},
		Status:     cosiv1alpha2.BucketAccessStatus{ReadyToUse: ptr.To(true)},
	}
	kubeClient, statusErr := newStatusFailingCOSIClient(access)
	reconciler := &BucketAccessReconciler{Client: kubeClient}
	originalErr := errors.New("original BucketAccess reconcile failure")

	result, err := reconciler.fail(t.Context(), access, originalErr)

	// The returned error causes controller-runtime to retry this reconcile. The
	// original failure must remain discoverable alongside the write failure.
	require.Equal(t, reconcile.Result{}, result)
	require.ErrorIs(t, err, originalErr)
	require.ErrorIs(t, err, statusErr)
}
