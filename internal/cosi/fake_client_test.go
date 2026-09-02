package cosi

import (
	"context"

	"k8s.io/apimachinery/pkg/util/uuid"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	cosiv1alpha2 "sigs.k8s.io/container-object-storage-interface/client/apis/objectstorage/v1alpha2"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
)

// newCOSIClientBuilder gives unit-test creates the API-server identity and
// status-subresource behavior that COSI's reservation protocol relies on.
func newCOSIClientBuilder() *fake.ClientBuilder {
	return fake.NewClientBuilder().
		WithStatusSubresource(
			&garagev1beta1.GarageBucket{}, &garagev1beta1.GarageKey{},
			&cosiv1alpha2.Bucket{}, &cosiv1alpha2.BucketAccess{},
		).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if obj.GetUID() == "" {
					obj.SetUID(uuid.NewUUID())
				}
				return c.Create(ctx, obj, opts...)
			},
		})
}
