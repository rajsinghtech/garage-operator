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

package controller

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

var _ = Describe("publicEndpoint reconciliation", func() {
	const (
		peClusterName = "pe-test-cluster"
		peNamespace   = testNamespace
	)

	var (
		reconciler *GarageClusterReconciler
		nn         types.NamespacedName
	)

	BeforeEach(func() {
		nn = types.NamespacedName{Name: peClusterName, Namespace: peNamespace}
		reconciler = &GarageClusterReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
	})

	AfterEach(func() {
		cluster := &garagev1beta2.GarageCluster{}
		if err := k8sClient.Get(ctx, nn, cluster); err == nil {
			cluster.Finalizers = nil
			_ = k8sClient.Update(ctx, cluster)
			_ = k8sClient.Delete(ctx, cluster)
		}
		for _, name := range []string{peClusterName, peClusterName + "-headless", peClusterName + "-rpc", peClusterName + "-0-rpc", peClusterName + "-1-rpc", peClusterName + "-2-rpc"} {
			_ = k8sClient.Delete(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: peNamespace}})
		}
		_ = k8sClient.Delete(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: peClusterName + "-config", Namespace: peNamespace}})
		_ = k8sClient.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: peClusterName + "-rpc-secret", Namespace: peNamespace}})
	})

	reconcileTwice := func() {
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
		Expect(err).NotTo(HaveOccurred())
		_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
		Expect(err).NotTo(HaveOccurred())
	}

	Context("LoadBalancer type", func() {
		It("creates a dedicated RPC service of type LoadBalancer", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: peClusterName, Namespace: peNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage:     &garagev1beta2.StorageSpec{Replicas: 1, Metadata: &garagev1beta2.VolumeConfig{}, Data: &garagev1beta2.VolumeConfig{}},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
					PublicEndpoint: &garagev1beta2.PublicEndpointConfig{
						Type: publicEndpointTypeLoadBalancer,
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			reconcileTwice()

			rpcSvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: peClusterName + "-rpc", Namespace: peNamespace}, rpcSvc)).To(Succeed())
			Expect(rpcSvc.Spec.Type).To(Equal(corev1.ServiceTypeLoadBalancer))
			Expect(rpcSvc.Spec.Ports).To(ContainElement(
				HaveField("Port", int32(3901)),
			))
		})

		It("uses the cluster ownership selector in Manual layout mode", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: peClusterName, Namespace: peNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: LayoutPolicyManual,
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 0,
						Metadata: &garagev1beta2.VolumeConfig{},
						Data:     &garagev1beta2.VolumeConfig{},
					},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
					PublicEndpoint: &garagev1beta2.PublicEndpointConfig{
						Type: publicEndpointTypeLoadBalancer,
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			Expect(reconciler.reconcilePublicEndpointService(ctx, cluster)).To(Succeed())

			rpcSvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: peClusterName + "-rpc", Namespace: peNamespace}, rpcSvc)).To(Succeed())
			Expect(rpcSvc.Spec.Selector).To(Equal(map[string]string{
				labelCluster: peClusterName,
			}))
		})

		It("sets rpc_public_addr in config once the LB service has an external IP", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: peClusterName, Namespace: peNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage:     &garagev1beta2.StorageSpec{Replicas: 1, Metadata: &garagev1beta2.VolumeConfig{}, Data: &garagev1beta2.VolumeConfig{}},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
					PublicEndpoint: &garagev1beta2.PublicEndpointConfig{
						Type: publicEndpointTypeLoadBalancer,
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			reconcileTwice()

			// Simulate LoadBalancer getting an external IP
			rpcSvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: peClusterName + "-rpc", Namespace: peNamespace}, rpcSvc)).To(Succeed())
			rpcSvc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.5"}}
			Expect(k8sClient.Status().Update(ctx, rpcSvc)).To(Succeed())

			// Reconcile again so config is regenerated with the LB IP
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			cm := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: peClusterName + "-config", Namespace: peNamespace}, cm)).To(Succeed())
			Expect(cm.Data["garage.toml"]).To(ContainSubstring(`rpc_public_addr = "10.0.0.5:3901"`))
		})

		It("prefers explicit network.rpcPublicAddr over publicEndpoint auto-derived address", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: peClusterName, Namespace: peNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage:     &garagev1beta2.StorageSpec{Replicas: 1, Metadata: &garagev1beta2.VolumeConfig{}, Data: &garagev1beta2.VolumeConfig{}},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
					Network: garagev1beta2.NetworkConfig{
						RPCPublicAddr: "explicit.example.com:3901",
					},
					PublicEndpoint: &garagev1beta2.PublicEndpointConfig{
						Type: publicEndpointTypeLoadBalancer,
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			reconcileTwice()

			// Simulate LB IP assignment
			rpcSvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: peClusterName + "-rpc", Namespace: peNamespace}, rpcSvc)).To(Succeed())
			rpcSvc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.5"}}
			Expect(k8sClient.Status().Update(ctx, rpcSvc)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			cm := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: peClusterName + "-config", Namespace: peNamespace}, cm)).To(Succeed())
			Expect(cm.Data["garage.toml"]).To(ContainSubstring(`rpc_public_addr = "explicit.example.com:3901"`))
			Expect(cm.Data["garage.toml"]).NotTo(ContainSubstring("10.0.0.5"))
		})

		It("creates per-node LoadBalancer RPC services when perNode is true", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: peClusterName, Namespace: peNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage:     &garagev1beta2.StorageSpec{Replicas: 2, Metadata: &garagev1beta2.VolumeConfig{}, Data: &garagev1beta2.VolumeConfig{}},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
					PublicEndpoint: &garagev1beta2.PublicEndpointConfig{
						Type: publicEndpointTypeLoadBalancer,
						LoadBalancer: &garagev1beta2.LoadBalancerEndpointConfig{
							PerNode: true,
							ServiceMeta: garagev1beta2.ServiceMeta{
								Annotations: map[string]string{"metallb.universe.tf/address-pool": "garage-rpc"},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			shared := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: peClusterName + "-rpc", Namespace: peNamespace},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{{Name: rpcPortName, Port: 3901}},
				},
			}
			Expect(k8sClient.Create(ctx, shared)).To(Succeed())

			reconcileTwice()

			err := k8sClient.Get(ctx, types.NamespacedName{Name: peClusterName + "-rpc", Namespace: peNamespace}, &corev1.Service{})
			Expect(k8serrors.IsNotFound(err)).To(BeTrue())

			for _, podName := range []string{peClusterName + "-0", peClusterName + "-1"} {
				rpcSvc := &corev1.Service{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: podName + "-rpc", Namespace: peNamespace}, rpcSvc)).To(Succeed())
				Expect(rpcSvc.Spec.Type).To(Equal(corev1.ServiceTypeLoadBalancer))
				Expect(rpcSvc.Spec.Selector).To(HaveKeyWithValue("statefulset.kubernetes.io/pod-name", podName))
				Expect(rpcSvc.Spec.Ports).To(ContainElement(HaveField("Port", int32(3901))))
				Expect(rpcSvc.Annotations).To(HaveKeyWithValue("metallb.universe.tf/address-pool", "garage-rpc"))
			}

			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, nn, updated)).To(Succeed())
			cond := findCondition(updated.Status.Conditions, garagev1beta1.ConditionPublicEndpointReady)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		})

		It("surfaces per-node cluster public endpoints as unsupported in Manual layout mode", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: peClusterName, Namespace: peNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: LayoutPolicyManual,
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 2,
						Metadata: &garagev1beta2.VolumeConfig{},
						Data:     &garagev1beta2.VolumeConfig{},
					},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
					PublicEndpoint: &garagev1beta2.PublicEndpointConfig{
						Type: publicEndpointTypeLoadBalancer,
						LoadBalancer: &garagev1beta2.LoadBalancerEndpointConfig{
							PerNode: true,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			Expect(reconciler.reconcilePublicEndpointService(ctx, cluster)).To(Succeed())

			for _, name := range []string{peClusterName + "-rpc", peClusterName + "-0-rpc", peClusterName + "-1-rpc"} {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: peNamespace}, &corev1.Service{})
				Expect(k8serrors.IsNotFound(err)).To(BeTrue(), "service %s should not be created", name)
			}
			cond := findCondition(cluster.Status.Conditions, garagev1beta1.ConditionPublicEndpointReady)
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal(garagev1beta1.ReasonPerNodeNotImplemented))
			Expect(cond.Message).To(ContainSubstring("GarageNode"))
		})
	})

	Context("NodePort type", func() {
		It("creates a NodePort RPC service and sets rpc_public_addr from externalAddresses", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: peClusterName, Namespace: peNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage:     &garagev1beta2.StorageSpec{Replicas: 1, Metadata: &garagev1beta2.VolumeConfig{}, Data: &garagev1beta2.VolumeConfig{}},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
					PublicEndpoint: &garagev1beta2.PublicEndpointConfig{
						Type: publicEndpointTypeNodePort,
						NodePort: &garagev1beta2.NodePortEndpointConfig{
							ExternalAddresses: []string{"k8s-node.example.com"},
							BasePort:          30901,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			reconcileTwice()

			rpcSvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: peClusterName + "-rpc", Namespace: peNamespace}, rpcSvc)).To(Succeed())
			Expect(rpcSvc.Spec.Type).To(Equal(corev1.ServiceTypeNodePort))

			cm := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: peClusterName + "-config", Namespace: peNamespace}, cm)).To(Succeed())
			Expect(cm.Data["garage.toml"]).To(ContainSubstring(`rpc_public_addr = "k8s-node.example.com:30901"`))
		})
	})

	Context("cleanup", func() {
		It("deletes the RPC service when publicEndpoint is removed from the spec", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: peClusterName, Namespace: peNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage:     &garagev1beta2.StorageSpec{Replicas: 1, Metadata: &garagev1beta2.VolumeConfig{}, Data: &garagev1beta2.VolumeConfig{}},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
					PublicEndpoint: &garagev1beta2.PublicEndpointConfig{
						Type: publicEndpointTypeLoadBalancer,
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			reconcileTwice()

			// Verify RPC service was created
			rpcSvc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: peClusterName + "-rpc", Namespace: peNamespace}, rpcSvc)).To(Succeed())

			// Remove publicEndpoint
			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, nn, updated)).To(Succeed())
			updated.Spec.PublicEndpoint = nil
			Expect(k8sClient.Update(ctx, updated)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())

			// RPC service should be gone
			err = k8sClient.Get(ctx, types.NamespacedName{Name: peClusterName + "-rpc", Namespace: peNamespace}, &corev1.Service{})
			Expect(k8serrors.IsNotFound(err)).To(BeTrue())
		})
	})

	Context("gateway connectTo missing admin token", func() {
		It("sets GatewayConnected=False condition when connectTo is configured but admin token is missing", func() {
			// Create the RPC secret that connectTo references
			rpcSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "pe-unraid-rpc-secret", Namespace: peNamespace},
				StringData: map[string]string{"rpc-secret": strings.Repeat("a", 64)},
			}
			_ = k8sClient.Delete(ctx, rpcSecret)
			Expect(k8sClient.Create(ctx, rpcSecret)).To(Succeed())

			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: peClusterName, Namespace: peNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					Gateway:     &garagev1beta2.GatewaySpec{Replicas: 1},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
					ConnectTo: &garagev1beta2.ConnectToConfig{
						RPCSecretRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "pe-unraid-rpc-secret"},
							Key:                  "rpc-secret",
						},
						AdminAPIEndpoint: "http://192.168.0.13:3903",
						AdminTokenSecretRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "pe-unraid-admin-token"},
							Key:                  "admin-token",
						},
					},
					// No spec.admin configured — gateway's own admin API is unauthenticated/unconfigured
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			reconcileTwice()

			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, nn, updated)).To(Succeed())

			cond := findCondition(updated.Status.Conditions, garagev1beta1.ConditionGatewayConnected)
			Expect(cond).NotTo(BeNil(), "GatewayConnected condition should be set")
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal(garagev1beta1.ReasonAdminTokenMissing))
		})
	})

	Context("deriveGatewayExternalAddr", func() {
		It("returns rpcPublicAddr directly when set", func() {
			// Regression: previously returned "" when rpcPublicAddr was set, causing the
			// reverse ConnectNode call to skip gateway nodes with no self-reported address.
			cluster := &garagev1beta2.GarageCluster{
				Spec: garagev1beta2.GarageClusterSpec{
					Gateway: &garagev1beta2.GatewaySpec{Replicas: 1},
					Network: garagev1beta2.NetworkConfig{
						RPCPublicAddr: "192.168.0.53:3901",
					},
				},
			}
			addr := reconciler.deriveGatewayExternalAddr(ctx, cluster)
			Expect(addr).To(Equal("192.168.0.53:3901"))
		})

		It("returns empty when neither rpcPublicAddr nor publicEndpoint is configured", func() {
			cluster := &garagev1beta2.GarageCluster{
				Spec: garagev1beta2.GarageClusterSpec{
					Gateway: &garagev1beta2.GatewaySpec{Replicas: 1},
				},
			}
			addr := reconciler.deriveGatewayExternalAddr(ctx, cluster)
			Expect(addr).To(BeEmpty())
		})

		It("returns the matching per-node LoadBalancer address when perNode is true", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: peClusterName, Namespace: peNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					PublicEndpoint: &garagev1beta2.PublicEndpointConfig{
						Type: publicEndpointTypeLoadBalancer,
						LoadBalancer: &garagev1beta2.LoadBalancerEndpointConfig{
							PerNode: true,
						},
					},
				},
			}

			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: peClusterName + "-0-rpc", Namespace: peNamespace},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{{Name: rpcPortName, Port: 3901}},
				},
			}
			Expect(k8sClient.Create(ctx, svc)).To(Succeed())
			svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.6"}}
			Expect(k8sClient.Status().Update(ctx, svc)).To(Succeed())

			addr := reconciler.deriveGatewayExternalAddrForNode(ctx, cluster, garage.NodeInfo{
				Hostname: ptrString(peClusterName + "-0"),
			})
			Expect(addr).To(Equal("10.0.0.6:3901"))
		})
	})
})

func ptrString(v string) *string {
	return &v
}

func findCondition(conditions []metav1.Condition, condType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}
