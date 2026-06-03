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
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// testBootstrapPeer is a fixed Garage node ID @ host:port used as a stub
// bootstrap peer in controller tests so they don't need a live cluster.
const testBootstrapPeer = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@example.com:3901"

// legacyLabelKey is used as a placeholder label on seeded pre-upgrade objects
// (e.g. v0.5.5 gateway Deployments) in controller tests.
const legacyLabelKey = "legacy"

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
				Namespace: testNamespace,
			}
		})

		AfterEach(func() {
			// Cleanup the GarageCluster
			cluster := &garagev1beta2.GarageCluster{}
			err := k8sClient.Get(ctx, typeNamespacedName, cluster)
			if err == nil {
				// Remove finalizer to allow deletion
				cluster.Finalizers = nil
				_ = k8sClient.Update(ctx, cluster)
				_ = k8sClient.Delete(ctx, cluster)
			}

			// Cleanup created resources
			_ = k8sClient.Delete(ctx, &appsv1.StatefulSet{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: testNamespace},
			})
			_ = k8sClient.Delete(ctx, &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName + "-gateway", Namespace: testNamespace},
			})
			_ = k8sClient.Delete(ctx, &appsv1.StatefulSet{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName + "-gateway", Namespace: testNamespace},
			})
			_ = k8sClient.Delete(ctx, &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: testNamespace},
			})
			_ = k8sClient.Delete(ctx, &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName + "-headless", Namespace: testNamespace},
			})
			_ = k8sClient.Delete(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName + "-config", Namespace: testNamespace},
			})
			_ = k8sClient.Delete(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName + "-rpc-secret", Namespace: testNamespace},
			})
		})

		It("should create the necessary Kubernetes resources", func() {
			By("Creating the GarageCluster resource")
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 3,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Replication: &garagev1beta2.ReplicationConfig{
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

			By("Verifying per-node GarageNodes were created (Auto mode, #190)")
			// Post-#190 the cluster-level storage STS is no longer reconciled;
			// instead one operator-owned GarageNode per replica is created and the
			// GarageNode controller owns each per-node StatefulSet.
			Eventually(func() (int, error) {
				gnList := &garagev1beta1.GarageNodeList{}
				if err := k8sClient.List(ctx, gnList,
					client.InNamespace(testNamespace),
					client.MatchingLabels(map[string]string{
						labelCluster:      resourceName,
						labelTier:         tierStorage,
						labelAppManagedBy: managedByOperatorValue,
					}),
				); err != nil {
					return 0, err
				}
				return len(gnList.Items), nil
			}, timeout, interval).Should(Equal(3))

			By("Verifying the headless Service was created")
			headlessSvc := &corev1.Service{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      resourceName + "-headless",
					Namespace: testNamespace,
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
					Namespace: testNamespace,
				}, cm)
			}, timeout, interval).Should(Succeed())
			Expect(cm.Data).To(HaveKey("garage.toml"))

			By("Verifying the RPC secret was created")
			secret := &corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      resourceName + "-rpc-secret",
					Namespace: testNamespace,
				}, secret)
			}, timeout, interval).Should(Succeed())
			Expect(secret.Data).To(HaveKey("rpc-secret"))
		})

		It("should preserve an explicit gateway replicas: 0", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta2.GarageClusterSpec{
					Gateway:     &garagev1beta2.GatewaySpec{Replicas: 0},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
					ConnectTo: &garagev1beta2.ConnectToConfig{
						BootstrapPeers: []string{testBootstrapPeer},
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			reconciler := &GarageClusterReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			Expect(reconciler.reconcileGatewayStatefulSet(ctx, cluster, "test-config-hash")).To(Succeed())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: resourceName + "-gateway", Namespace: testNamespace}, sts)).To(Succeed())
			Expect(sts.Spec.Replicas).NotTo(BeNil())
			Expect(*sts.Spec.Replicas).To(Equal(int32(0)))

			// Gateway pods carry a bind-only TCP readiness probe by default (gating
			// on the cluster-wide write-quorum /health would collapse the anycast at
			// factor 2 — see buildGaragePodSpec). It's behind the <cr>-gateway Service
			// (PublishNotReadyAddresses=false), so the probe keeps surge pods out of
			// the endpoint slice until Garage has bound :3900. A custom serving-aware
			// gate can be supplied via spec.gateway.readinessProbe.
			Expect(sts.Spec.Template.Spec.Containers).To(HaveLen(1))
			probe := sts.Spec.Template.Spec.Containers[0].ReadinessProbe
			Expect(probe).NotTo(BeNil(), "gateway pod must have a readiness probe")
			Expect(probe.TCPSocket).NotTo(BeNil(), "gateway default readiness must be bind-only TCP")
			Expect(probe.TCPSocket.Port.StrVal).To(Equal(s3PortName))
		})

		It("should provision a 1Gi metadata PVC for gateway pods by default", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta2.GarageClusterSpec{
					Gateway:     &garagev1beta2.GatewaySpec{Replicas: 2},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
					ConnectTo: &garagev1beta2.ConnectToConfig{
						BootstrapPeers: []string{testBootstrapPeer},
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			reconciler := &GarageClusterReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			Expect(reconciler.reconcileGatewayStatefulSet(ctx, cluster, "test-config-hash")).To(Succeed())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: resourceName + "-gateway", Namespace: testNamespace}, sts)).To(Succeed())

			// Metadata PVC template at default size.
			Expect(sts.Spec.VolumeClaimTemplates).To(HaveLen(1), "gateway statefulset must have exactly one PVC template (metadata)")
			meta := sts.Spec.VolumeClaimTemplates[0]
			Expect(meta.Name).To(Equal(metadataVolName))
			req := meta.Spec.Resources.Requests[corev1.ResourceStorage]
			Expect(req.String()).To(Equal("1Gi"))

			// Data dir must NOT be templated as a PVC — it is EmptyDir.
			for _, vct := range sts.Spec.VolumeClaimTemplates {
				Expect(vct.Name).NotTo(Equal(dataVolName))
			}
			var dataVol *corev1.Volume
			for i, v := range sts.Spec.Template.Spec.Volumes {
				if v.Name == dataVolName {
					dataVol = &sts.Spec.Template.Spec.Volumes[i]
				}
			}
			Expect(dataVol).NotTo(BeNil(), "gateway pod must declare a data volume")
			Expect(dataVol.EmptyDir).NotTo(BeNil(), "gateway data volume must be EmptyDir")

			// PVC retention is Delete/Delete to match the prior ephemeral semantics.
			Expect(sts.Spec.PersistentVolumeClaimRetentionPolicy).NotTo(BeNil())
			Expect(sts.Spec.PersistentVolumeClaimRetentionPolicy.WhenScaled).To(Equal(appsv1.DeletePersistentVolumeClaimRetentionPolicyType))
			Expect(sts.Spec.PersistentVolumeClaimRetentionPolicy.WhenDeleted).To(Equal(appsv1.DeletePersistentVolumeClaimRetentionPolicyType))
		})

		It("should honor a user-supplied gateway metadata size", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta2.GarageClusterSpec{
					Gateway: &garagev1beta2.GatewaySpec{
						Replicas: 2,
						Metadata: &garagev1beta2.VolumeConfig{
							Size: ptrQuantity(resource.MustParse("2Gi")),
						},
					},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
					ConnectTo: &garagev1beta2.ConnectToConfig{
						BootstrapPeers: []string{testBootstrapPeer},
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			reconciler := &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			Expect(reconciler.reconcileGatewayStatefulSet(ctx, cluster, "test-config-hash")).To(Succeed())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: resourceName + "-gateway", Namespace: testNamespace}, sts)).To(Succeed())
			Expect(sts.Spec.VolumeClaimTemplates).To(HaveLen(1))
			req := sts.Spec.VolumeClaimTemplates[0].Spec.Resources.Requests[corev1.ResourceStorage]
			Expect(req.String()).To(Equal("2Gi"))
		})

		It("should delete a pre-existing gateway Deployment when reconciling the StatefulSet (one-shot upgrade aid)", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta2.GarageClusterSpec{
					Gateway:     &garagev1beta2.GatewaySpec{Replicas: 1},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
					ConnectTo: &garagev1beta2.ConnectToConfig{
						BootstrapPeers: []string{testBootstrapPeer},
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			// Seed a pre-existing Deployment with the gateway workload name, as
			// upgrades from v0.5.5 would have.
			oldDeploy := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName + "-gateway",
					Namespace: testNamespace,
					Labels:    map[string]string{legacyLabelKey: annotationTrue},
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](1),
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{legacyLabelKey: annotationTrue}},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{legacyLabelKey: annotationTrue}},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: defaultAppName, Image: defaultGarageImage}},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, oldDeploy)).To(Succeed())

			reconciler := &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			Expect(reconciler.reconcileGatewayStatefulSet(ctx, cluster, "test-config-hash")).To(Succeed())

			// The pre-existing Deployment must be deleted.
			fresh := &appsv1.Deployment{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: resourceName + "-gateway", Namespace: testNamespace}, fresh)
			Expect(errors.IsNotFound(err)).To(BeTrue(), "pre-existing gateway Deployment must be removed when StatefulSet is reconciled")

			// The new StatefulSet must exist in its place.
			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: resourceName + "-gateway", Namespace: testNamespace}, sts)).To(Succeed())
		})

		It("should publish the GarageNode selector in Manual layout mode status", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
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
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			reconciler := &GarageClusterReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			_, err := reconciler.updateStatusFromCluster(ctx, cluster)
			Expect(err).NotTo(HaveOccurred())

			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
			Expect(updated.Status.Selector).To(Equal(labelCluster + "=" + resourceName))
		})

		It("preserves computed status across a status-update conflict", func() {
			// Unique cluster name so the status computation (which counts this
			// cluster's GarageNodes) is not contaminated by operator-owned nodes
			// other specs leave behind in this shared namespace (envtest has no
			// garbage collector to reap them on cluster delete).
			const cName = "status-conflict-cluster"
			cNN := types.NamespacedName{Name: cName, Namespace: testNamespace}
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: cName, Namespace: testNamespace},
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
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, cluster) })

			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: cName + "-node-0", Namespace: testNamespace},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: cName},
					Capacity:   ptrQuantity(resource.MustParse("10Gi")),
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, node)
			})
			node.Status.Connected = true
			Expect(k8sClient.Status().Update(ctx, node)).To(Succeed())

			reconciler := &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}

			// Fetch a STALE copy, then mutate the live object so the stale copy's
			// ResourceVersion is out of date and the first Status().Update inside
			// updateStatusFromCluster hits a 409, forcing the re-fetch+re-apply path.
			clusterStale := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, cNN, clusterStale)).To(Succeed())

			fresh := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, cNN, fresh)).To(Succeed())
			// A valid-but-different Phase bumps the live ResourceVersion so the
			// stale copy's Status().Update hits a 409 — the closure must re-fetch
			// and re-apply the computed "Running", overwriting this "Degraded".
			fresh.Status.Phase = "Degraded"
			Expect(k8sClient.Status().Update(ctx, fresh)).To(Succeed())

			_, err := reconciler.updateStatusFromCluster(ctx, clusterStale)
			Expect(err).NotTo(HaveOccurred())

			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, cNN, updated)).To(Succeed())
			Expect(updated.Status.ReadyReplicas).To(Equal(int32(1)))
			Expect(updated.Status.Replicas).To(Equal(int32(1)))
			Expect(updated.Status.Phase).To(Equal("Running"))
		})

		It("should add a finalizer to the GarageCluster", func() {
			By("Creating the GarageCluster resource")
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 1,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Replication: &garagev1beta2.ReplicationConfig{
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
			updatedCluster := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedCluster)).To(Succeed())
			Expect(updatedCluster.Finalizers).To(ContainElement(garageClusterFinalizer))
		})

		It("should use custom ports when specified", func() {
			By("Creating a GarageCluster with custom ports")
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 1,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Replication: &garagev1beta2.ReplicationConfig{
						Factor: 1,
					},
					S3API: &garagev1beta2.S3APIConfig{
						BindPort: 4900,
					},
					Admin: &garagev1beta2.AdminConfig{
						BindPort: 4903,
					},
					Network: garagev1beta2.NetworkConfig{
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
					Namespace: testNamespace,
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
					Name:      testNonExistent,
					Namespace: testNamespace,
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
				Namespace: testNamespace,
			}

			// Create the external secret
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testExternalRPCSecret,
					Namespace: testNamespace,
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
			cluster := &garagev1beta2.GarageCluster{}
			err := k8sClient.Get(ctx, typeNamespacedName, cluster)
			if err == nil {
				cluster.Finalizers = nil
				_ = k8sClient.Update(ctx, cluster)
				_ = k8sClient.Delete(ctx, cluster)
			}
			_ = k8sClient.Delete(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: testExternalRPCSecret, Namespace: testNamespace},
			})
		})

		It("should use the external RPC secret", func() {
			By("Creating a GarageCluster with external RPC secret reference")
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage: &garagev1beta2.StorageSpec{
						Replicas: 1,
						Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Replication: &garagev1beta2.ReplicationConfig{
						Factor: 1,
					},
					Network: garagev1beta2.NetworkConfig{
						RPCSecretRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: testExternalRPCSecret,
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
				Namespace: testNamespace,
			}, autoSecret)
			Expect(errors.IsNotFound(err)).To(BeTrue())
		})
	})
})

// Regression guard for #196: spec.storage.podDisruptionBudget was a no-op
// after #192 removed the legacy reconcilePDB along with the cluster-level
// StatefulSet. The replacement reconcile lives on the cluster controller and
// targets the storage tier via {labelCluster, labelTier=storage} so it
// covers every per-node StatefulSet introduced in #190.
var _ = Describe("GarageCluster PodDisruptionBudget reconcile", func() {
	const clusterName = "pdb-cluster"
	var (
		ctx        context.Context
		reconciler *GarageClusterReconciler
		key        types.NamespacedName
	)

	BeforeEach(func() {
		ctx = context.Background()
		reconciler = &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		key = types.NamespacedName{Name: clusterName, Namespace: testNamespace}
	})

	AfterEach(func() {
		// Drop finalizer first so Delete actually GC's — the cluster's normal
		// finalizer makes admin-API calls that envtest can't service.
		cluster := &garagev1beta2.GarageCluster{}
		if err := k8sClient.Get(ctx, key, cluster); err == nil {
			cluster.Finalizers = nil
			_ = k8sClient.Update(ctx, cluster)
			_ = k8sClient.Delete(ctx, cluster)
		}
		_ = k8sClient.Delete(ctx, &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace}})
		_ = k8sClient.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: clusterName + "-rpc-secret", Namespace: testNamespace}})
		_ = k8sClient.Delete(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: clusterName + "-config", Namespace: testNamespace}})
	})

	newCluster := func(pdb *garagev1beta2.PodDisruptionBudgetConfig) *garagev1beta2.GarageCluster {
		return &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace},
			Spec: garagev1beta2.GarageClusterSpec{
				Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
				Storage: &garagev1beta2.StorageSpec{
					Replicas:            3,
					Metadata:            &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:                &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					PodDisruptionBudget: pdb,
				},
			},
		}
	}

	driveReconciles := func() {
		// Twice — first adds finalizer, second creates resources.
		for i := 0; i < 2; i++ {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key})
			Expect(err).NotTo(HaveOccurred())
		}
	}

	It("defaults MinAvailable to replicas-1 to preserve quorum on drain", func() {
		// newCluster sets storage.replicas=3 → expect MinAvailable=2.
		Expect(k8sClient.Create(ctx, newCluster(&garagev1beta2.PodDisruptionBudgetConfig{Enabled: true}))).To(Succeed())
		driveReconciles()

		pdb := &policyv1.PodDisruptionBudget{}
		Expect(k8sClient.Get(ctx, key, pdb)).To(Succeed())
		Expect(pdb.Spec.MinAvailable).NotTo(BeNil())
		Expect(pdb.Spec.MinAvailable.IntValue()).To(Equal(2))
		Expect(pdb.Spec.MaxUnavailable).To(BeNil())
		// Selector matches the pre-#192 shape so existing PDBs upgrade in place
		// (spec.selector is immutable).
		Expect(pdb.Spec.Selector.MatchLabels).To(HaveKeyWithValue(labelAppName, defaultAppName))
		Expect(pdb.Spec.Selector.MatchLabels).To(HaveKeyWithValue(labelAppInstance, clusterName))
		Expect(pdb.Spec.Selector.MatchLabels).To(HaveKeyWithValue(labelTier, tierStorage))
	})

	It("honors an explicit MaxUnavailable", func() {
		one := intstr.FromInt(1)
		Expect(k8sClient.Create(ctx, newCluster(&garagev1beta2.PodDisruptionBudgetConfig{Enabled: true, MaxUnavailable: &one}))).To(Succeed())
		driveReconciles()

		pdb := &policyv1.PodDisruptionBudget{}
		Expect(k8sClient.Get(ctx, key, pdb)).To(Succeed())
		Expect(pdb.Spec.MinAvailable).To(BeNil())
		Expect(pdb.Spec.MaxUnavailable).NotTo(BeNil())
		Expect(pdb.Spec.MaxUnavailable.IntValue()).To(Equal(1))
	})

	It("deletes the PDB when enabled flips to false", func() {
		Expect(k8sClient.Create(ctx, newCluster(&garagev1beta2.PodDisruptionBudgetConfig{Enabled: true}))).To(Succeed())
		driveReconciles()
		Expect(k8sClient.Get(ctx, key, &policyv1.PodDisruptionBudget{})).To(Succeed())

		updated := &garagev1beta2.GarageCluster{}
		Expect(k8sClient.Get(ctx, key, updated)).To(Succeed())
		updated.Spec.Storage.PodDisruptionBudget.Enabled = false
		Expect(k8sClient.Update(ctx, updated)).To(Succeed())
		driveReconciles()

		Expect(errors.IsNotFound(k8sClient.Get(ctx, key, &policyv1.PodDisruptionBudget{}))).To(BeTrue())
	})

	It("does not create a PDB when the field is omitted", func() {
		Expect(k8sClient.Create(ctx, newCluster(nil))).To(Succeed())
		driveReconciles()

		Expect(errors.IsNotFound(k8sClient.Get(ctx, key, &policyv1.PodDisruptionBudget{}))).To(BeTrue())
	})

	It("uses maxUnavailable=1 for a single-replica cluster (keeps it drainable)", func() {
		size := resource.MustParse("1Gi")
		Expect(k8sClient.Create(ctx, &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace},
			Spec: garagev1beta2.GarageClusterSpec{
				Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
				Storage: &garagev1beta2.StorageSpec{
					Replicas:            1,
					Metadata:            &garagev1beta2.VolumeConfig{Size: &size},
					Data:                &garagev1beta2.VolumeConfig{Size: &size},
					PodDisruptionBudget: &garagev1beta2.PodDisruptionBudgetConfig{Enabled: true},
				},
			},
		})).To(Succeed())
		driveReconciles()

		pdb := &policyv1.PodDisruptionBudget{}
		Expect(k8sClient.Get(ctx, key, pdb)).To(Succeed())
		// A single-replica tier stays drainable via maxUnavailable=1, not minAvailable=1.
		Expect(pdb.Spec.MinAvailable).To(BeNil())
		Expect(pdb.Spec.MaxUnavailable.IntValue()).To(Equal(1))
	})

	It("leaves a foreign PDB with the same name alone (no ownerRef)", func() {
		foreign := &policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: testNamespace,
				Labels:    map[string]string{"managed-by": "policy-engine"},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "policy.example.com/v1",
					Kind:       "PolicyTemplate",
					Name:       "external",
					UID:        "00000000-0000-0000-0000-000000000001",
					Controller: ptr.To(true),
				}},
			},
			Spec: policyv1.PodDisruptionBudgetSpec{
				Selector:     &metav1.LabelSelector{MatchLabels: map[string]string{"foreign": annotationTrue}},
				MinAvailable: ptr.To(intstr.FromInt(7)),
			},
		}
		Expect(k8sClient.Create(ctx, foreign)).To(Succeed())

		Expect(k8sClient.Create(ctx, newCluster(&garagev1beta2.PodDisruptionBudgetConfig{Enabled: true}))).To(Succeed())
		driveReconciles()

		got := &policyv1.PodDisruptionBudget{}
		Expect(k8sClient.Get(ctx, key, got)).To(Succeed())
		Expect(got.Spec.MinAvailable.IntValue()).To(Equal(7))
		Expect(got.Spec.Selector.MatchLabels).To(HaveKeyWithValue("foreign", "true"))

		// And the foreign PDB also isn't deleted when wantPDB=false.
		updated := &garagev1beta2.GarageCluster{}
		Expect(k8sClient.Get(ctx, key, updated)).To(Succeed())
		updated.Spec.Storage.PodDisruptionBudget.Enabled = false
		Expect(k8sClient.Update(ctx, updated)).To(Succeed())
		driveReconciles()
		Expect(k8sClient.Get(ctx, key, &policyv1.PodDisruptionBudget{})).To(Succeed())

		_ = k8sClient.Delete(ctx, foreign)
	})
})

// Mirror of the storage PDB tests for the gateway tier (#199). Gateway PDB is
// named "<cluster>-gateway" so it can coexist with the storage PDB.
var _ = Describe("GarageCluster gateway PodDisruptionBudget reconcile", func() {
	const clusterName = "pdb-gw-cluster"
	var (
		ctx        context.Context
		reconciler *GarageClusterReconciler
		gwKey      types.NamespacedName
	)

	BeforeEach(func() {
		ctx = context.Background()
		reconciler = &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		gwKey = types.NamespacedName{Name: clusterName + "-gateway", Namespace: testNamespace}
	})

	AfterEach(func() {
		cluster := &garagev1beta2.GarageCluster{}
		clusterKey := types.NamespacedName{Name: clusterName, Namespace: testNamespace}
		if err := k8sClient.Get(ctx, clusterKey, cluster); err == nil {
			cluster.Finalizers = nil
			_ = k8sClient.Update(ctx, cluster)
			_ = k8sClient.Delete(ctx, cluster)
		}
		_ = k8sClient.Delete(ctx, &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace}})
		_ = k8sClient.Delete(ctx, &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: clusterName + "-gateway", Namespace: testNamespace}})
		_ = k8sClient.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: clusterName + "-rpc-secret", Namespace: testNamespace}})
		_ = k8sClient.Delete(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: clusterName + "-config", Namespace: testNamespace}})
	})

	// Unified cluster — storage + gateway. Storage is required so HasGatewayTier
	// reconcile alone doesn't trip the "gateway without storage/connectTo" webhook.
	newUnifiedCluster := func(gwPDB *garagev1beta2.PodDisruptionBudgetConfig, gwReplicas int32) *garagev1beta2.GarageCluster {
		return &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace},
			Spec: garagev1beta2.GarageClusterSpec{
				Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 3,
					Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
				},
				Gateway: &garagev1beta2.GatewaySpec{
					Replicas:            gwReplicas,
					PodDisruptionBudget: gwPDB,
				},
			},
		}
	}

	driveReconciles := func() {
		for i := 0; i < 2; i++ {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: clusterName, Namespace: testNamespace}})
			Expect(err).NotTo(HaveOccurred())
		}
	}

	It("creates a tier-specific PDB named <cluster>-gateway", func() {
		Expect(k8sClient.Create(ctx, newUnifiedCluster(&garagev1beta2.PodDisruptionBudgetConfig{Enabled: true}, 3))).To(Succeed())
		driveReconciles()

		pdb := &policyv1.PodDisruptionBudget{}
		Expect(k8sClient.Get(ctx, gwKey, pdb)).To(Succeed())
		Expect(pdb.Spec.MinAvailable).NotTo(BeNil())
		Expect(pdb.Spec.MinAvailable.IntValue()).To(Equal(2))
		Expect(pdb.Spec.Selector.MatchLabels).To(HaveKeyWithValue(labelTier, tierGateway))
	})

	It("honors explicit maxUnavailable as in the issue", func() {
		one := intstr.FromInt(1)
		Expect(k8sClient.Create(ctx, newUnifiedCluster(&garagev1beta2.PodDisruptionBudgetConfig{Enabled: true, MaxUnavailable: &one}, 3))).To(Succeed())
		driveReconciles()

		pdb := &policyv1.PodDisruptionBudget{}
		Expect(k8sClient.Get(ctx, gwKey, pdb)).To(Succeed())
		Expect(pdb.Spec.MinAvailable).To(BeNil())
		Expect(pdb.Spec.MaxUnavailable).NotTo(BeNil())
		Expect(pdb.Spec.MaxUnavailable.IntValue()).To(Equal(1))
	})

	It("makes a single-replica gateway PDB drainable via maxUnavailable=1", func() {
		Expect(k8sClient.Create(ctx, newUnifiedCluster(&garagev1beta2.PodDisruptionBudgetConfig{Enabled: true}, 1))).To(Succeed())
		driveReconciles()

		pdb := &policyv1.PodDisruptionBudget{}
		Expect(k8sClient.Get(ctx, gwKey, pdb)).To(Succeed())
		Expect(pdb.Spec.MinAvailable).To(BeNil())
		Expect(pdb.Spec.MaxUnavailable).NotTo(BeNil())
		Expect(pdb.Spec.MaxUnavailable.IntValue()).To(Equal(1))
	})

	It("does not create a PDB when gateway replicas is 0", func() {
		Expect(k8sClient.Create(ctx, newUnifiedCluster(&garagev1beta2.PodDisruptionBudgetConfig{Enabled: true}, 0))).To(Succeed())
		driveReconciles()

		Expect(errors.IsNotFound(k8sClient.Get(ctx, gwKey, &policyv1.PodDisruptionBudget{}))).To(BeTrue())
	})

	It("does not create a PDB when the field is omitted", func() {
		Expect(k8sClient.Create(ctx, newUnifiedCluster(nil, 3))).To(Succeed())
		driveReconciles()

		Expect(errors.IsNotFound(k8sClient.Get(ctx, gwKey, &policyv1.PodDisruptionBudget{}))).To(BeTrue())
	})

	It("deletes the gateway PDB when enabled flips to false", func() {
		Expect(k8sClient.Create(ctx, newUnifiedCluster(&garagev1beta2.PodDisruptionBudgetConfig{Enabled: true}, 3))).To(Succeed())
		driveReconciles()
		Expect(k8sClient.Get(ctx, gwKey, &policyv1.PodDisruptionBudget{})).To(Succeed())

		updated := &garagev1beta2.GarageCluster{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: clusterName, Namespace: testNamespace}, updated)).To(Succeed())
		updated.Spec.Gateway.PodDisruptionBudget.Enabled = false
		Expect(k8sClient.Update(ctx, updated)).To(Succeed())
		driveReconciles()

		Expect(errors.IsNotFound(k8sClient.Get(ctx, gwKey, &policyv1.PodDisruptionBudget{}))).To(BeTrue())
	})

	It("storage and gateway PDBs coexist on a unified cluster", func() {
		cluster := newUnifiedCluster(&garagev1beta2.PodDisruptionBudgetConfig{Enabled: true}, 3)
		cluster.Spec.Storage.PodDisruptionBudget = &garagev1beta2.PodDisruptionBudgetConfig{Enabled: true}
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
		driveReconciles()

		storagePDB := &policyv1.PodDisruptionBudget{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: clusterName, Namespace: testNamespace}, storagePDB)).To(Succeed())
		Expect(storagePDB.Spec.Selector.MatchLabels).To(HaveKeyWithValue(labelTier, tierStorage))

		gwPDB := &policyv1.PodDisruptionBudget{}
		Expect(k8sClient.Get(ctx, gwKey, gwPDB)).To(Succeed())
		Expect(gwPDB.Spec.Selector.MatchLabels).To(HaveKeyWithValue(labelTier, tierGateway))
	})
})
