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
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1alpha1 "github.com/rajsinghtech/garage-operator/api/v1alpha1"
)

var _ = Describe("GarageCluster Controller", func() {
	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	Context("When creating a new GarageCluster", func() {
		const resourceName = "test-cluster"
		var typeNamespacedName types.NamespacedName

		BeforeEach(func() {
			typeNamespacedName = types.NamespacedName{
				Name:      resourceName,
				Namespace: "default",
			}
		})

		AfterEach(func() {
			// Cleanup the GarageCluster
			cluster := &garagev1alpha1.GarageCluster{}
			err := k8sClient.Get(ctx, typeNamespacedName, cluster)
			if err == nil {
				// Remove finalizer to allow deletion
				cluster.Finalizers = nil
				_ = k8sClient.Update(ctx, cluster)
				_ = k8sClient.Delete(ctx, cluster)
			}

			// Cleanup created resources
			_ = k8sClient.Delete(ctx, &appsv1.StatefulSet{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: "default"},
			})
			_ = k8sClient.Delete(ctx, &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: "default"},
			})
			_ = k8sClient.Delete(ctx, &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName + "-headless", Namespace: "default"},
			})
			_ = k8sClient.Delete(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName + "-config", Namespace: "default"},
			})
			_ = k8sClient.Delete(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName + "-rpc-secret", Namespace: "default"},
			})
		})

		It("should create the necessary Kubernetes resources", func() {
			By("Creating the GarageCluster resource")
			cluster := &garagev1alpha1.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageClusterSpec{
					Replicas: 3,
					Replication: garagev1alpha1.ReplicationConfig{
						Factor: 3,
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			By("Reconciling the GarageCluster")
			reconciler := &GarageClusterReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Run reconcile again (first pass adds finalizer)
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the StatefulSet was created")
			sts := &appsv1.StatefulSet{}
			Eventually(func() error {
				return k8sClient.Get(ctx, typeNamespacedName, sts)
			}, timeout, interval).Should(Succeed())
			Expect(*sts.Spec.Replicas).To(Equal(int32(3)))

			By("Verifying the headless Service was created")
			headlessSvc := &corev1.Service{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      resourceName + "-headless",
					Namespace: "default",
				}, headlessSvc)
			}, timeout, interval).Should(Succeed())
			Expect(headlessSvc.Spec.ClusterIP).To(Equal("None"))

			By("Verifying the API Service was created")
			apiSvc := &corev1.Service{}
			Eventually(func() error {
				return k8sClient.Get(ctx, typeNamespacedName, apiSvc)
			}, timeout, interval).Should(Succeed())
			Expect(apiSvc.Spec.Type).To(Equal(corev1.ServiceTypeClusterIP))

			By("Verifying the ConfigMap was created")
			cm := &corev1.ConfigMap{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      resourceName + "-config",
					Namespace: "default",
				}, cm)
			}, timeout, interval).Should(Succeed())
			Expect(cm.Data).To(HaveKey("garage.toml"))

			By("Verifying the RPC secret was created")
			secret := &corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      resourceName + "-rpc-secret",
					Namespace: "default",
				}, secret)
			}, timeout, interval).Should(Succeed())
			Expect(secret.Data).To(HaveKey("rpc-secret"))
		})

		It("should add a finalizer to the GarageCluster", func() {
			By("Creating the GarageCluster resource")
			cluster := &garagev1alpha1.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageClusterSpec{
					Replicas: 1,
					Replication: garagev1alpha1.ReplicationConfig{
						Factor: 1,
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			By("Reconciling the GarageCluster")
			reconciler := &GarageClusterReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the finalizer was added")
			updatedCluster := &garagev1alpha1.GarageCluster{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedCluster)).To(Succeed())
			Expect(updatedCluster.Finalizers).To(ContainElement(garageClusterFinalizer))
		})

		It("should use custom ports when specified", func() {
			By("Creating a GarageCluster with custom ports")
			cluster := &garagev1alpha1.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageClusterSpec{
					Replicas: 1,
					Replication: garagev1alpha1.ReplicationConfig{
						Factor: 1,
					},
					S3API: &garagev1alpha1.S3APIConfig{
						BindPort: 4900,
					},
					Admin: &garagev1alpha1.AdminConfig{
						Enabled:  true,
						BindPort: 4903,
					},
					Network: garagev1alpha1.NetworkConfig{
						RPCBindPort: 4901,
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			By("Reconciling the GarageCluster")
			reconciler := &GarageClusterReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// First reconcile adds finalizer
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile creates resources
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying custom ports are used in the ConfigMap")
			cm := &corev1.ConfigMap{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      resourceName + "-config",
					Namespace: "default",
				}, cm)
			}, timeout, interval).Should(Succeed())
			Expect(cm.Data["garage.toml"]).To(ContainSubstring("4901"))
			Expect(cm.Data["garage.toml"]).To(ContainSubstring("4900"))
			Expect(cm.Data["garage.toml"]).To(ContainSubstring("4903"))
		})
	})

	Context("When reconciling a non-existent GarageCluster", func() {
		It("should return without error", func() {
			reconciler := &GarageClusterReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := reconciler.Reconcile(context.Background(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "non-existent",
					Namespace: "default",
				},
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("When using an external RPC secret", func() {
		const resourceName = "test-cluster-external-secret"
		var typeNamespacedName types.NamespacedName

		BeforeEach(func() {
			typeNamespacedName = types.NamespacedName{
				Name:      resourceName,
				Namespace: "default",
			}

			// Create the external secret
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "external-rpc-secret",
					Namespace: "default",
				},
				StringData: map[string]string{
					"my-key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				},
			}
			err := k8sClient.Create(ctx, secret)
			if err != nil && !errors.IsAlreadyExists(err) {
				Expect(err).NotTo(HaveOccurred())
			}
		})

		AfterEach(func() {
			// Cleanup
			cluster := &garagev1alpha1.GarageCluster{}
			err := k8sClient.Get(ctx, typeNamespacedName, cluster)
			if err == nil {
				cluster.Finalizers = nil
				_ = k8sClient.Update(ctx, cluster)
				_ = k8sClient.Delete(ctx, cluster)
			}
			_ = k8sClient.Delete(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "external-rpc-secret", Namespace: "default"},
			})
		})

		It("should use the external RPC secret", func() {
			By("Creating a GarageCluster with external RPC secret reference")
			cluster := &garagev1alpha1.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: garagev1alpha1.GarageClusterSpec{
					Replicas: 1,
					Replication: garagev1alpha1.ReplicationConfig{
						Factor: 1,
					},
					Network: garagev1alpha1.NetworkConfig{
						RPCSecretRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "external-rpc-secret",
							},
							Key: "my-key",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			By("Reconciling the GarageCluster")
			reconciler := &GarageClusterReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// First reconcile adds finalizer
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile creates resources
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying no auto-generated secret was created")
			autoSecret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      resourceName + "-rpc-secret",
				Namespace: "default",
			}, autoSecret)
			Expect(errors.IsNotFound(err)).To(BeTrue())
		})
	})
})
