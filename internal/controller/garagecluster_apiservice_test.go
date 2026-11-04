/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// These tests cover the tier-scoping behavior of the in-cluster API Services.
// The historical <cr> Service selected on instance=<cr> alone, which matches
// BOTH storage pods AND gateway pods. That round-robined
// admin/S3 traffic through gateway pods even when the storage tier was
// directly reachable. The fix scopes <cr> to the storage tier and adds a
// sibling <cr>-gateway Service for the gateway tier.
var _ = Describe("GarageCluster API Service tier scoping", func() {
	const ns = testNamespace

	var reconciler *GarageClusterReconciler
	BeforeEach(func() {
		reconciler = &GarageClusterReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
	})

	cleanupSvcs := func(name string) {
		_ = k8sClient.Delete(ctx, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		})
		_ = k8sClient.Delete(ctx, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: name + "-gateway", Namespace: ns},
		})
		gc := &garagev1beta2.GarageCluster{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, gc); err == nil {
			gc.Finalizers = nil
			_ = k8sClient.Update(ctx, gc)
			_ = k8sClient.Delete(ctx, gc)
		}
	}

	// createCluster persists the CR so reconcileService can set an
	// OwnerReference with a real UID.
	createCluster := func(c *garagev1beta2.GarageCluster) {
		Expect(k8sClient.Create(ctx, c)).To(Succeed())
	}

	Context("unified cluster (storage + gateway)", func() {
		const name = "tier-svc-unified"

		AfterEach(func() {
			cleanupSvcs(name)
		})

		It("creates <cr> with tier:storage and <cr>-gateway with tier:gateway, same port set", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 3,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Gateway:     &garagev1beta2.GatewaySpec{Replicas: 2},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 3},
				},
			}
			createCluster(cluster)

			Expect(reconciler.reconcileAPIService(ctx, cluster)).To(Succeed())
			Expect(reconciler.reconcileGatewayAPIService(ctx, cluster)).To(Succeed())

			storageSvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, storageSvc)).To(Succeed())
			Expect(storageSvc.Spec.Selector).To(HaveKeyWithValue(labelTier, tierStorage))
			Expect(storageSvc.Spec.Selector).NotTo(HaveKey(labelAppManagedBy))

			gatewaySvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name + "-gateway", Namespace: ns}, gatewaySvc)).To(Succeed())
			Expect(gatewaySvc.Spec.Selector).To(HaveKeyWithValue(labelTier, tierGateway))

			// Port sets must match exactly so in-cluster clients can target
			// either tier interchangeably.
			Expect(servicePortNames(storageSvc)).To(Equal(servicePortNames(gatewaySvc)))
			Expect(servicePortNames(storageSvc)).To(ContainElements("s3", adminPortName, "web"))
		})
	})

	Context("storage-only cluster", func() {
		const name = "tier-svc-storage-only"

		AfterEach(func() {
			cleanupSvcs(name)
		})

		It("creates <cr> with tier:storage and no <cr>-gateway Service", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 3,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 3},
				},
			}
			createCluster(cluster)

			Expect(reconciler.reconcileAPIService(ctx, cluster)).To(Succeed())
			// Mirror the controller loop: when no gateway tier, ensure the
			// sibling service is absent (and stays absent).
			Expect(reconciler.deleteGatewayAPIService(ctx, cluster)).To(Succeed())

			storageSvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, storageSvc)).To(Succeed())
			Expect(storageSvc.Spec.Selector).To(HaveKeyWithValue(labelTier, tierStorage))

			gatewaySvc := &corev1.Service{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: name + "-gateway", Namespace: ns}, gatewaySvc)
			Expect(errors.IsNotFound(err)).To(BeTrue(), "<cr>-gateway Service must not exist for storage-only clusters")
		})
	})

	Context("edge-gateway cluster (no storage, has connectTo)", func() {
		const name = "tier-svc-edge-gateway"

		AfterEach(func() {
			cleanupSvcs(name)
		})

		It("creates <cr> with tier:gateway and no <cr>-gateway Service", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: garagev1beta2.GarageClusterSpec{
					Gateway:     &garagev1beta2.GatewaySpec{Replicas: 1},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
					ConnectTo: &garagev1beta2.ConnectToConfig{
						BootstrapPeers: []string{
							testBootstrapPeer,
						},
					},
				},
			}
			createCluster(cluster)

			Expect(reconciler.reconcileAPIService(ctx, cluster)).To(Succeed())
			Expect(reconciler.deleteGatewayAPIService(ctx, cluster)).To(Succeed())

			primarySvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, primarySvc)).To(Succeed())
			// Edge gateway has no local storage tier — primary <cr> points at
			// the gateway pods directly.
			Expect(primarySvc.Spec.Selector).To(HaveKeyWithValue(labelTier, tierGateway))

			gatewaySvc := &corev1.Service{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: name + "-gateway", Namespace: ns}, gatewaySvc)
			Expect(errors.IsNotFound(err)).To(BeTrue(), "<cr>-gateway Service is redundant for edge-gateway clusters")
		})
	})

	Context("removing the gateway tier from a unified CR", func() {
		const name = "tier-svc-shrink"

		AfterEach(func() {
			cleanupSvcs(name)
		})

		It("deletes the <cr>-gateway Service", func() {
			unified := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 3,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Gateway:     &garagev1beta2.GatewaySpec{Replicas: 2},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 3},
				},
			}
			createCluster(unified)
			Expect(reconciler.reconcileAPIService(ctx, unified)).To(Succeed())
			Expect(reconciler.reconcileGatewayAPIService(ctx, unified)).To(Succeed())

			gatewaySvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name + "-gateway", Namespace: ns}, gatewaySvc)).To(Succeed())

			// User edits the CR and removes spec.gateway.
			shrunk := unified.DeepCopy()
			shrunk.Spec.Gateway = nil
			Expect(reconciler.deleteGatewayAPIService(ctx, shrunk)).To(Succeed())

			err := k8sClient.Get(ctx, types.NamespacedName{Name: name + "-gateway", Namespace: ns}, gatewaySvc)
			Expect(errors.IsNotFound(err)).To(BeTrue())
		})
	})

	Context("Manual layout policy", func() {
		const name = "tier-svc-manual"

		AfterEach(func() {
			cleanupSvcs(name)
		})

		It("scopes to {labelCluster, labelTier=storage, api-serving} — GarageNode pods carry all three", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: LayoutPolicyManual,
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 1,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
				},
			}
			createCluster(cluster)

			Expect(reconciler.reconcileAPIService(ctx, cluster)).To(Succeed())

			svc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, svc)).To(Succeed())
			// Post-#190/#535: per-node GarageNode pods carry {labelCluster,
			// labelTier=storage, api-serving=true} but NOT instance=<cr> or
			// name=garage. api-serving clears during drain without flipping
			// NLP pods off tier=storage; gateway pods never match.
			Expect(svc.Spec.Selector).To(Equal(map[string]string{
				labelCluster:    name,
				labelTier:       tierStorage,
				labelAPIServing: annotationTrue,
			}))
		})
	})
})

var _ = Describe("GarageCluster API Service IP families", func() {
	const name = "api-svc-ip-family"

	AfterEach(func() {
		_ = k8sClient.Delete(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace}})
		_ = k8sClient.Delete(ctx, &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace}})
	})

	It("switches an existing SingleStack Service to PreferDualStack in place", func() {
		reconciler := &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
				},
				Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
			},
		}
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
		key := types.NamespacedName{Name: name, Namespace: testNamespace}

		Expect(reconciler.reconcileAPIService(ctx, cluster)).To(Succeed())
		original := &corev1.Service{}
		Expect(k8sClient.Get(ctx, key, original)).To(Succeed())

		preferDualStack := corev1.IPFamilyPolicyPreferDualStack
		cluster.Spec.Network.Service = &garagev1beta2.ServiceConfig{IPFamilyPolicy: &preferDualStack}
		Expect(reconciler.reconcileAPIService(ctx, cluster)).To(Succeed())
		switched := &corev1.Service{}
		Expect(k8sClient.Get(ctx, key, switched)).To(Succeed())
		Expect(switched.UID).To(Equal(original.UID))
		Expect(switched.Spec.IPFamilyPolicy).To(HaveValue(Equal(corev1.IPFamilyPolicyPreferDualStack)))
	})
})

func servicePortNames(svc *corev1.Service) []string {
	names := make([]string, 0, len(svc.Spec.Ports))
	for _, p := range svc.Spec.Ports {
		names = append(names, p.Name)
	}
	return names
}

// Pure-unit test for apiServiceSelector: storage tier must select
// {labelCluster, labelTier=storage, api-serving=true} in both Auto and Manual
// layout policies (#190/#535). Storage is per-node GarageNode-owned in both
// modes; those pods don't carry the unified instance label, and drain clears
// api-serving without changing NLP tier=storage.
var _ = Describe("apiServiceSelector storage-tier selector", func() {
	const apiSelectorNS = "apiselector-ns"
	r := &GarageClusterReconciler{}

	It("returns {cluster, tier=storage, api-serving} for Auto layout storage tier", func() {
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "auto-cluster", Namespace: apiSelectorNS},
			Spec: garagev1beta2.GarageClusterSpec{
				LayoutPolicy: LayoutPolicyAuto,
			},
		}
		Expect(r.apiServiceSelector(cluster, tierStorage)).To(Equal(map[string]string{
			labelCluster:    "auto-cluster",
			labelTier:       tierStorage,
			labelAPIServing: annotationTrue,
		}))
	})

	It("returns {cluster, tier=storage, api-serving} for Manual layout storage tier", func() {
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "manual-cluster", Namespace: apiSelectorNS},
			Spec: garagev1beta2.GarageClusterSpec{
				LayoutPolicy: LayoutPolicyManual,
			},
		}
		Expect(r.apiServiceSelector(cluster, tierStorage)).To(Equal(map[string]string{
			labelCluster:    "manual-cluster",
			labelTier:       tierStorage,
			labelAPIServing: annotationTrue,
		}))
	})

	It("keeps the unified tier selector for the gateway tier", func() {
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: testEdgeValue, Namespace: apiSelectorNS},
		}
		Expect(r.apiServiceSelector(cluster, tierGateway)).To(Equal(map[string]string{
			labelAppName:     defaultAppName,
			labelAppInstance: testEdgeValue,
			labelTier:        tierGateway,
		}))
	})
})

var _ = Describe("managed Admin API endpoint", func() {
	It("derives Services and container ports from admin.bindAddress", func() {
		cluster := &garagev1beta2.GarageCluster{Spec: garagev1beta2.GarageClusterSpec{
			Admin: &garagev1beta2.AdminConfig{BindPort: 3903, BindAddress: "[::]:4903"},
		}}
		Expect(getAdminPort(cluster)).To(Equal(int32(4903)))

		servicePorts := apiServicePorts(cluster)
		adminServicePort := int32(0)
		for i := range servicePorts {
			if servicePorts[i].Name == adminPortName {
				adminServicePort = servicePorts[i].Port
				Expect(servicePorts[i].TargetPort.IntVal).To(Equal(int32(4903)))
			}
		}
		Expect(adminServicePort).To(Equal(int32(4903)))

		containerPorts := buildContainerPorts(cluster)
		adminContainerPort := int32(0)
		for i := range containerPorts {
			if containerPorts[i].Name == adminPortName {
				adminContainerPort = containerPorts[i].ContainerPort
			}
		}
		Expect(adminContainerPort).To(Equal(int32(4903)))
	})

	It("fails closed for an Admin API address that a managed Pod Service cannot reach", func() {
		cluster := &garagev1beta2.GarageCluster{Spec: garagev1beta2.GarageClusterSpec{
			Admin: &garagev1beta2.AdminConfig{BindAddress: "127.0.0.1:4903"},
		}}
		_, err := managedAdminPort(cluster)
		Expect(err).To(MatchError(ContainSubstring("not a wildcard address")))
	})
})
