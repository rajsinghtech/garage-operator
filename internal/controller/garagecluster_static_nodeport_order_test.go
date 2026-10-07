package controller

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// nodePortAllocator models the apiserver's NodePort allocator for Service
// Creates: explicit nodePorts must be free, and unset ones are drawn from the
// range. It allocates adversarially (the lowest free port of the dynamic
// band), which is what the random allocator did in External Gateway E2E run
// 37509963663 when it handed publicEndpoint's basePort 30901 to the
// cluster's own API Service.
type nodePortAllocator struct {
	next      int32
	allocated map[int32]string
}

func (a *nodePortAllocator) create(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
	svc, ok := obj.(*corev1.Service)
	if !ok || (svc.Spec.Type != corev1.ServiceTypeNodePort && svc.Spec.Type != corev1.ServiceTypeLoadBalancer) {
		return c.Create(ctx, obj, opts...)
	}
	for i := range svc.Spec.Ports {
		port := &svc.Spec.Ports[i]
		if port.NodePort == 0 {
			continue
		}
		if owner, taken := a.allocated[port.NodePort]; taken {
			return apierrors.NewInvalid(schema.GroupKind{Kind: "Service"}, svc.Name, field.ErrorList{
				field.Invalid(field.NewPath("spec", "ports").Index(i).Child("nodePort"), port.NodePort,
					fmt.Sprintf("provided port is already allocated (by %s)", owner)),
			})
		}
	}
	for i := range svc.Spec.Ports {
		port := &svc.Spec.Ports[i]
		if port.NodePort == 0 {
			for a.allocated[a.next] != "" {
				a.next++
			}
			port.NodePort = a.next
		}
		a.allocated[port.NodePort] = svc.Name
	}
	return c.Create(ctx, obj, opts...)
}

// TestPublicEndpointStaticNodePortsAreReservedBeforeAPIService: the
// publicEndpoint RPC Service's user-chosen nodePort must be reserved before
// the NodePort API Service asks the allocator for ports, or the cluster's own
// API Service can take it and the RPC Service fails on every reconcile.
func TestPublicEndpointStaticNodePortsAreReservedBeforeAPIService(t *testing.T) {
	ctx := context.Background()
	const basePort = int32(30901)
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "ext-gateway", Namespace: "garage", UID: types.UID("ext-gateway-uid")},
		Spec: garagev1beta2.GarageClusterSpec{
			Gateway: &garagev1beta2.GatewaySpec{Replicas: 1},
			Network: garagev1beta2.NetworkConfig{
				Service: &garagev1beta2.ServiceConfig{Type: corev1.ServiceTypeNodePort},
			},
			PublicEndpoint: &garagev1beta2.PublicEndpointConfig{
				Type: publicEndpointTypeNodePort,
				NodePort: &garagev1beta2.NodePortEndpointConfig{
					BasePort:          basePort,
					ExternalAddresses: []string{"172.30.0.2"},
				},
			},
		},
	}
	scheme := testSchemeForFault(t)
	alloc := &nodePortAllocator{next: basePort, allocated: map[int32]string{}}
	kube := interceptor.NewClient(
		fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster).Build(),
		interceptor.Funcs{Create: alloc.create},
	)
	r := &GarageClusterReconciler{Client: kube, Scheme: scheme}

	if err := r.reconcileClusterServices(ctx, cluster); err != nil {
		t.Fatalf("reconciling cluster Services: %v", err)
	}
	if owner := alloc.allocated[basePort]; owner != cluster.Name+"-rpc" {
		t.Fatalf("nodePort %d must belong to the publicEndpoint RPC Service, got %q", basePort, owner)
	}
	api := &corev1.Service{}
	if err := kube.Get(ctx, types.NamespacedName{Namespace: cluster.Namespace, Name: cluster.Name}, api); err != nil {
		t.Fatalf("API Service: %v", err)
	}
	for _, port := range api.Spec.Ports {
		if port.NodePort == basePort {
			t.Fatalf("API Service port %s took the publicEndpoint nodePort %d", port.Name, basePort)
		}
	}
	// A second pass is a no-op Update, not a re-allocation.
	if err := r.reconcileClusterServices(ctx, cluster); err != nil {
		t.Fatalf("second pass: %v", err)
	}
}
