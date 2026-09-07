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
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
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

const hostileLabelTestImage = "example.invalid/label-test"

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
			_ = deleteTestGarageNodesForCluster(ctx, k8sClient, testNamespace, resourceName)
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
			_ = deleteTestGarageConfigResourcesForCluster(ctx, k8sClient, resourceName)
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
			var cm *corev1.ConfigMap
			Eventually(func() error {
				var err error
				cm, err = testConfigMapForBase(ctx, k8sClient, testNamespace, resourceName+"-config")
				return err
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
			Expect(secret.Immutable).NotTo(BeNil())
			Expect(*secret.Immutable).To(BeTrue())
			Expect(k8sClient.Get(ctx, typeNamespacedName, cluster)).To(Succeed())
			Expect(cluster.Annotations).To(HaveKey(annotationRPCIdentitySHA256))

			By("refusing to regenerate a deleted identity after bootstrap")
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			Eventually(func() bool {
				return errors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(secret), &corev1.Secret{}))
			}, timeout, interval).Should(BeTrue())
			_, err = reconciler.ensureRPCSecret(ctx, cluster)
			Expect(err).To(MatchError(ContainSubstring("refusing to generate a different identity")))
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
			Expect(sts.Spec.Template.Annotations).To(HaveKeyWithValue(
				annotationGatewayDataMarker, gatewayDataMarkerLegacyContent,
			), "edge gateway Pods must project the legacy empty data marker")

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

		It("keeps edge gateway selector and Scale labels operator-owned", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					Gateway: &garagev1beta2.GatewaySpec{
						Replicas: 1,
						PodTemplate: garagev1beta2.PodTemplate{PodLabels: map[string]string{
							labelAppName: "hostile", labelAppInstance: "wrong-instance",
							labelAppManagedBy: "wrong-manager", labelCluster: "wrong-gateway-cluster",
							labelTier: tierStorage, labelStorageGroup: storageGroupDefault,
							labelScaleTarget: scaleTargetDisabled, "example.com/gateway-label": "gateway-kept",
						}},
					},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
					ConnectTo: &garagev1beta2.ConnectToConfig{
						BootstrapPeers: []string{testBootstrapPeer},
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			r := &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			Expect(r.reconcileGatewayStatefulSet(ctx, cluster, "test-config-hash")).To(Succeed())

			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: resourceName + "-gateway", Namespace: testNamespace}, sts)).To(Succeed())
			for key, value := range sts.Spec.Selector.MatchLabels {
				Expect(sts.Spec.Template.Labels).To(HaveKeyWithValue(key, value))
			}
			Expect(sts.Spec.Template.Labels).To(HaveKeyWithValue(labelAppName, defaultAppName))
			Expect(sts.Spec.Template.Labels).To(HaveKeyWithValue(labelAppInstance, resourceName))
			Expect(sts.Spec.Template.Labels).To(HaveKeyWithValue(labelAppManagedBy, operatorName))
			Expect(sts.Spec.Template.Labels).To(HaveKeyWithValue(labelCluster, resourceName))
			Expect(sts.Spec.Template.Labels).To(HaveKeyWithValue(labelTier, tierGateway))
			Expect(sts.Spec.Template.Labels).NotTo(HaveKey(labelStorageGroup))
			Expect(sts.Spec.Template.Labels).NotTo(HaveKey(labelScaleTarget))
			Expect(sts.Spec.Template.Labels).To(HaveKeyWithValue("example.com/gateway-label", "gateway-kept"))

			gatewayPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: "gateway-scale-pod", Namespace: testNamespace, Labels: map[string]string{},
			}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: fmGarageContainer, Image: hostileLabelTestImage}}}}
			for key, value := range sts.Spec.Template.Labels {
				gatewayPod.Labels[key] = value
			}
			storagePod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: "gateway-scale-storage-pod", Namespace: testNamespace,
				Labels: map[string]string{labelCluster: resourceName, labelTier: tierStorage},
			}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: fmGarageContainer, Image: hostileLabelTestImage}}}}
			Expect(k8sClient.Create(ctx, gatewayPod)).To(Succeed())
			Expect(k8sClient.Create(ctx, storagePod)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, gatewayPod)
				_ = k8sClient.Delete(ctx, storagePod)
			})

			observation, err := r.observeGarageClusterScale(ctx, cluster)
			Expect(err).NotTo(HaveOccurred())
			Expect(observation.replicas).To(Equal(int32(1)))
			Expect(observation.selector).To(Equal(
				"garage.rajsingh.info/cluster=" + resourceName + ",garage.rajsingh.info/tier=gateway",
			))
		})

		It("pins an existing generated-name RPC Secret without replacing its identity", func() {
			rpcValue := testTerminalNodeID
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage:     &garagev1beta2.StorageSpec{Replicas: 0},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			preexisting := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            resourceName + "-rpc-secret",
					Namespace:       testNamespace,
					OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster))},
				},
				Data: map[string][]byte{RPCSecretKey: []byte(rpcValue)},
			}
			Expect(k8sClient.Create(ctx, preexisting)).To(Succeed())
			reconciler := &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			Expect(k8sClient.Get(ctx, typeNamespacedName, cluster)).To(Succeed())
			pinned, err := reconciler.ensureRPCSecret(ctx, cluster)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(pinned.Data[RPCSecretKey])).To(Equal(rpcValue))
			Expect(pinned.Immutable).NotTo(BeNil())
			Expect(*pinned.Immutable).To(BeTrue())
			Expect(k8sClient.Get(ctx, typeNamespacedName, cluster)).To(Succeed())
			Expect(cluster.Annotations).To(HaveKey(annotationRPCIdentitySHA256))
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

		It("should honor and update an explicit edge-gateway PVC retention policy", func() {
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					Gateway: &garagev1beta2.GatewaySpec{
						Replicas: 0,
						PVCRetentionPolicy: &garagev1beta2.PVCRetentionPolicy{
							WhenDeleted: testRetentionRetain, WhenScaled: pvcRetentionDelete,
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
			key := types.NamespacedName{Name: resourceName + "-gateway", Namespace: testNamespace}
			sts := &appsv1.StatefulSet{}
			Expect(k8sClient.Get(ctx, key, sts)).To(Succeed())
			Expect(sts.Spec.PersistentVolumeClaimRetentionPolicy).NotTo(BeNil())
			Expect(sts.Spec.PersistentVolumeClaimRetentionPolicy.WhenDeleted).
				To(Equal(appsv1.RetainPersistentVolumeClaimRetentionPolicyType))
			Expect(sts.Spec.PersistentVolumeClaimRetentionPolicy.WhenScaled).
				To(Equal(appsv1.DeletePersistentVolumeClaimRetentionPolicyType))

			cluster.Spec.Gateway.PVCRetentionPolicy = &garagev1beta2.PVCRetentionPolicy{
				WhenDeleted: pvcRetentionDelete, WhenScaled: testRetentionRetain,
			}
			Expect(reconciler.reconcileGatewayStatefulSet(ctx, cluster, "test-config-hash")).To(Succeed())
			Expect(k8sClient.Get(ctx, key, sts)).To(Succeed())
			Expect(sts.Spec.PersistentVolumeClaimRetentionPolicy.WhenDeleted).
				To(Equal(appsv1.DeletePersistentVolumeClaimRetentionPolicyType))
			Expect(sts.Spec.PersistentVolumeClaimRetentionPolicy.WhenScaled).
				To(Equal(appsv1.RetainPersistentVolumeClaimRetentionPolicyType))
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
			Expect(controllerutil.SetControllerReference(cluster, oldDeploy, k8sClient.Scheme())).To(Succeed())
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

		It("promptly retries a ready edge gateway until live health is observable", func() {
			const clusterName = "health-retry-edge-gateway"
			clusterKey := types.NamespacedName{Name: clusterName, Namespace: testNamespace}
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					Admin: &garagev1beta2.AdminConfig{AdminTokenSecretRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "health-retry-missing-token"},
						Key:                  DefaultAdminTokenKey,
					}},
					Gateway:     &garagev1beta2.GatewaySpec{Replicas: 1},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
					ConnectTo: &garagev1beta2.ConnectToConfig{
						BootstrapPeers: []string{testBootstrapPeer},
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, cluster) })
			cluster.Status.Health = &garagev1beta2.ClusterHealth{
				Status: healthStatusHealthy, Healthy: true, Available: true,
				KnownNodes: 1, ConnectedNodes: 1, StorageNodes: 1, StorageNodesOK: 1,
			}
			Expect(k8sClient.Status().Update(ctx, cluster)).To(Succeed())

			labels := map[string]string{"app": clusterName}
			gateway := &appsv1.StatefulSet{
				ObjectMeta: metav1.ObjectMeta{Name: gatewayWorkloadName(cluster), Namespace: testNamespace},
				Spec: appsv1.StatefulSetSpec{
					Replicas:    ptr.To[int32](1),
					ServiceName: clusterName,
					Selector:    &metav1.LabelSelector{MatchLabels: labels},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{Labels: labels},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: defaultAppName, Image: defaultGarageImage}},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, gateway) })
			gateway.Status.Replicas = 1
			gateway.Status.ReadyReplicas = 1
			Expect(k8sClient.Status().Update(ctx, gateway)).To(Succeed())

			// No managed Pod or verified operator token exists, which models the
			// transient Admin API gap immediately after an external layout apply.
			// Seed a previously healthy value above to prove an unavailable current
			// observation cannot leave stale Healthy status behind.
			reconciler := &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			result, err := reconciler.updateStatusFromCluster(ctx, cluster)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(RequeueAfterUnhealthy),
				"unknown live health must override the normal five-minute edge-gateway interval")

			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, clusterKey, updated)).To(Succeed())
			Expect(updated.Status.Health).To(BeNil())
		})

		It("uses the stable cadence for a ready storage cluster with no configured Admin credential", func() {
			const clusterName = "tokenless-health-cadence"
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage: &garagev1beta2.StorageSpec{LayoutPolicy: LayoutPolicyManual},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, cluster) })

			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName + "-node", Namespace: testNamespace},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
					Zone:       "zone-a",
					Capacity:   ptrQuantity(resource.MustParse("1Gi")),
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, node) })
			node.Status.NodeID = testTerminalNodeID
			node.Status.Connected = true
			node.Status.InLayout = true
			node.Status.ObservedGeneration = node.Generation
			Expect(k8sClient.Status().Update(ctx, node)).To(Succeed())

			reconciler := &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			result, err := reconciler.updateStatusFromCluster(ctx, cluster)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(RequeueAfterShort),
				"absence of optional Admin auth must not be treated as a transient health failure")
		})

		It("keeps a converged node-local cluster Ready when a sibling layout reconcile owns the mutex", func() {
			const clusterName = "node-local-layout-contention"
			clusterKey := types.NamespacedName{Name: clusterName, Namespace: testNamespace}
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage: &garagev1beta2.StorageSpec{LayoutPolicy: LayoutPolicyManual},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, cluster) })

			transitionTime := metav1.Now()
			cluster.Status.Phase = PhaseFailed
			cluster.Status.Conditions = []metav1.Condition{
				{
					Type:               garagev1beta1.ConditionNodeLocalPoolsReady,
					Status:             metav1.ConditionTrue,
					Reason:             garagev1beta1.ReasonNodeLocalPoolsConverged,
					Message:            "node-local-pool members are connected",
					ObservedGeneration: cluster.Generation,
					LastTransitionTime: transitionTime,
				},
				{
					Type:               garagev1beta1.ConditionStorageRolloutReady,
					Status:             metav1.ConditionTrue,
					Reason:             garagev1beta1.ReasonStorageRolloutConverged,
					Message:            "all managed identities are ready",
					ObservedGeneration: cluster.Generation,
					LastTransitionTime: transitionTime,
				},
				{
					Type:               PhaseReady,
					Status:             metav1.ConditionFalse,
					Reason:             garagev1beta1.ReasonReconcileFailed,
					Message:            "another reconciler is changing Garage layout",
					ObservedGeneration: cluster.Generation,
					LastTransitionTime: transitionTime,
				},
			}
			Expect(k8sClient.Status().Update(ctx, cluster)).To(Succeed())

			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName + "-worker", Namespace: testNamespace},
				Spec: garagev1beta1.GarageNodeSpec{
					Backing:            garagev1beta1.NodeBackingNodeLocalPool,
					Capacity:           ptrQuantity(resource.MustParse("100Gi")),
					ClusterRef:         garagev1beta1.ClusterReference{Name: clusterName},
					NodeLocalPoolName:  "local",
					KubernetesNodeName: "worker",
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, node) })
			node.Status.NodeID = testTerminalNodeID
			node.Status.Connected = true
			node.Status.InLayout = true
			node.Status.ObservedGeneration = node.Generation
			Expect(k8sClient.Status().Update(ctx, node)).To(Succeed())

			reconciler := &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			result, err := reconciler.updateStatusAfterNodeLocalPoolContention(
				ctx,
				cluster,
				fmt.Errorf("%w: another reconciler is changing Garage layout", errLayoutMutationPending),
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(RequeueAfterError))

			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, clusterKey, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal(PhaseRunning))
			ready := meta.FindStatusCondition(updated.Status.Conditions, PhaseReady)
			Expect(ready).NotTo(BeNil())
			Expect(ready.Status).To(Equal(metav1.ConditionTrue))
			Expect(ready.Reason).To(Equal("ClusterReady"))
			poolReady := meta.FindStatusCondition(updated.Status.Conditions, garagev1beta1.ConditionNodeLocalPoolsReady)
			Expect(poolReady).NotTo(BeNil())
			Expect(poolReady.Status).To(Equal(metav1.ConditionTrue))
			Expect(poolReady.Reason).To(Equal(garagev1beta1.ReasonNodeLocalPoolsConverged))
		})

		It("reports rollout coordinator contention as a retryable wait and refreshes health", func() {
			const clusterName = "storage-rollout-contention"
			clusterKey := types.NamespacedName{Name: clusterName, Namespace: testNamespace}
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					Storage: &garagev1beta2.StorageSpec{LayoutPolicy: LayoutPolicyManual},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, cluster) })
			cluster.Status.Health = &garagev1beta2.ClusterHealth{
				Status: healthStatusHealthy, Healthy: true, Available: true,
				KnownNodes: 1, ConnectedNodes: 1, StorageNodes: 1, StorageNodesOK: 1,
			}
			Expect(k8sClient.Status().Update(ctx, cluster)).To(Succeed())

			node := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName + "-node", Namespace: testNamespace},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: clusterName},
					Zone:       "zone-a",
					Capacity:   ptrQuantity(resource.MustParse("1Gi")),
				},
			}
			Expect(k8sClient.Create(ctx, node)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, node) })
			node.Status.NodeID = testTerminalNodeID
			node.Status.Connected = true
			node.Status.InLayout = true
			node.Status.ObservedGeneration = node.Generation
			Expect(k8sClient.Status().Update(ctx, node)).To(Succeed())

			reconciler := &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			result, err := reconciler.updateStatusAfterStorageRolloutContention(
				ctx,
				cluster,
				fmt.Errorf("%w: another reconciler is changing Garage layout", errLayoutMutationPending),
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(RequeueAfterError))

			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, clusterKey, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal(PhaseRunning))
			Expect(updated.Status.Health).To(BeNil(), "a failed live observation must not retain stale health")
			rolloutReady := meta.FindStatusCondition(updated.Status.Conditions, garagev1beta1.ConditionStorageRolloutReady)
			Expect(rolloutReady).NotTo(BeNil())
			Expect(rolloutReady.Status).To(Equal(metav1.ConditionFalse))
			Expect(rolloutReady.Reason).To(Equal(garagev1beta1.ReasonStorageRolloutWaiting))
			phaseReady := meta.FindStatusCondition(updated.Status.Conditions, PhaseReady)
			Expect(phaseReady).NotTo(BeNil())
			Expect(phaseReady.Status).To(Equal(metav1.ConditionFalse))
			Expect(phaseReady.Reason).To(Equal("StorageRolloutNotReady"))
		})

		It("counts unlabeled clusterRef-matched GarageNodes toward readiness in Auto mode (#237)", func() {
			// Mirrors the robbinsdale incident: cluster-level Auto with a Manual
			// storage tier. The storage GarageNodes are hand-written and do NOT
			// carry the operator's cluster label; the gateway nodes (operator-
			// generated) do. Selecting children by label made the storage nodes
			// invisible to status aggregation: ready=2(gw) < desired=3 pinned the
			// phase at Degraded forever, which gated GarageKey provisioning.
			const cName = "unlabeled-manual-storage-cluster"
			cNN := types.NamespacedName{Name: cName, Namespace: testNamespace}
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: cName, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: LayoutPolicyAuto,
					Storage: &garagev1beta2.StorageSpec{
						Replicas:     1,
						LayoutPolicy: LayoutPolicyManual,
						Metadata:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
						Data:         &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
					},
					Gateway:     &garagev1beta2.GatewaySpec{Replicas: 2},
					Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, cluster) })

			mkNode := func(name string, gateway bool, labels map[string]string) {
				node := &garagev1beta1.GarageNode{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace, Labels: labels},
					Spec: garagev1beta1.GarageNodeSpec{
						ClusterRef: garagev1beta1.ClusterReference{Name: cName},
						Gateway:    gateway,
					},
				}
				if !gateway {
					node.Spec.Capacity = ptrQuantity(resource.MustParse("10Gi"))
				}
				Expect(k8sClient.Create(ctx, node)).To(Succeed())
				DeferCleanup(func() { _ = k8sClient.Delete(ctx, node) })
				node.Status.NodeID = name
				node.Status.Connected = true
				node.Status.InLayout = true
				node.Status.ObservedGeneration = node.Generation
				Expect(k8sClient.Status().Update(ctx, node)).To(Succeed())
			}

			// Operator-generated gateway nodes carry the cluster label.
			mkNode(cName+"-gateway-0", true, map[string]string{labelCluster: cName})
			mkNode(cName+"-gateway-1", true, map[string]string{labelCluster: cName})
			// Hand-managed Manual storage node: clusterRef matches, no labels.
			mkNode(cName+"-storage-smb", false, nil)

			reconciler := &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := reconciler.updateStatusFromCluster(ctx, cluster)
			Expect(err).NotTo(HaveOccurred())

			updated := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, cNN, updated)).To(Succeed())
			Expect(updated.Status.StorageReadyReplicas).To(Equal(int32(1)),
				"unlabeled storage GarageNode with matching clusterRef must count as ready")
			Expect(updated.Status.GatewayReadyReplicas).To(Equal(int32(2)))
			Expect(updated.Status.ReadyReplicas).To(Equal(int32(3)))
			Expect(updated.Status.Phase).To(Equal(PhaseRunning),
				"phase must not be pinned Degraded by label-less Manual storage nodes")
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
			node.Status.NodeID = node.Name
			node.Status.Connected = true
			node.Status.InLayout = true
			node.Status.ObservedGeneration = node.Generation
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

		It("never adopts a newer resourceVersion without its concurrent drain status", func() {
			const cName = "status-rv-adoption-cluster"
			cNN := types.NamespacedName{Name: cName, Namespace: testNamespace}
			cluster := &garagev1beta2.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: cName, Namespace: testNamespace},
				Spec: garagev1beta2.GarageClusterSpec{
					LayoutPolicy: LayoutPolicyManual,
					Storage:      &garagev1beta2.StorageSpec{},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, cluster) })

			stale := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, cNN, stale)).To(Succeed())
			fresh := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, cNN, fresh)).To(Succeed())
			proof := &blockResyncProof{
				Actor:                 storageDrainActorForCluster(fresh),
				TransactionID:         "rv-adoption-drain",
				StartedAt:             metav1.Now(),
				RoleRemovalNodeIDs:    []string{testOwnedNodeID},
				RemovedStorageNodeIDs: []string{testOwnedNodeID},
			}
			proof.TargetHash = storageDrainProofTargetHash(proof)
			fresh.Status.StorageDrain = v1beta2StorageDrainStatus(proof)
			setStorageDrainCondition(fresh, metav1.ConditionFalse, garagev1beta1.ReasonStorageDraining, "durable drain")
			Expect(k8sClient.Status().Update(ctx, fresh)).To(Succeed())

			reconciler := &GarageClusterReconciler{Client: k8sClient, APIReader: k8sClient}
			// This helper intentionally has no metadata change to make. It still
			// refreshes the object. Historically it copied only that refresh's RV
			// into stale, which let the next whole-status update erase the proof.
			Expect(reconciler.setOperatorMetricsTokenIntent(ctx, stale, false)).To(Succeed())
			Expect(stale.Status.StorageDrain).NotTo(BeNil())
			Expect(reconciler.setNodeLocalPoolsCondition(
				ctx, stale, metav1.ConditionFalse,
				garagev1beta1.ReasonNodeLocalPoolDraining, "concurrent pool status",
			)).To(Succeed())

			persisted := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, cNN, persisted)).To(Succeed())
			Expect(persisted.Status.StorageDrain).NotTo(BeNil())
			Expect(persisted.Status.StorageDrain.TransactionID).To(Equal(proof.TransactionID))
			Expect(meta.FindStatusCondition(
				persisted.Status.Conditions, garagev1beta1.ConditionStorageDrainReady,
			)).NotTo(BeNil())
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
			var cm *corev1.ConfigMap
			Eventually(func() error {
				var err error
				cm, err = testConfigMapForBase(ctx, k8sClient, testNamespace, resourceName+"-config")
				return err
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
			_ = k8sClient.Delete(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName + "-rpc-secret-snapshot", Namespace: testNamespace},
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

			By("Verifying the external value was pinned into one immutable canonical local Secret")
			snapshot := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      resourceName + "-rpc-secret-snapshot",
				Namespace: testNamespace,
			}, snapshot)
			Expect(err).NotTo(HaveOccurred())
			Expect(snapshot.Immutable).NotTo(BeNil())
			Expect(*snapshot.Immutable).To(BeTrue())
			Expect(string(snapshot.Data[RPCSecretKey])).To(Equal("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
			Expect(snapshot.Annotations).To(HaveKeyWithValue(
				annotationRPCIdentitySource, testNamespace+"/"+testExternalRPCSecret+":my-key",
			))
			Expect(k8sClient.Get(ctx, typeNamespacedName, cluster)).To(Succeed())
			Expect(cluster.Annotations).To(HaveKey(annotationRPCIdentitySHA256))

			By("failing closed when the mutable source drifts after bootstrap")
			external := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: testExternalRPCSecret, Namespace: testNamespace}, external)).To(Succeed())
			external.Data["my-key"] = []byte("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
			Expect(k8sClient.Update(ctx, external)).To(Succeed())
			_, err = reconciler.ensureRPCSecret(ctx, cluster)
			Expect(err).To(MatchError(ContainSubstring("no longer matches immutable snapshot")))
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
		_ = deleteTestGarageConfigResourcesForCluster(ctx, k8sClient, clusterName)
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
		cluster := &garagev1beta2.GarageCluster{}
		Expect(k8sClient.Get(ctx, key, cluster)).To(Succeed())
		Expect(reconciler.reconcileTierPodDisruptionBudget(ctx, cluster, tierStorage)).To(Succeed())
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

	It("defaults Manual storage membership to maxUnavailable=1 instead of the ignored replica field", func() {
		cluster := newCluster(&garagev1beta2.PodDisruptionBudgetConfig{Enabled: true})
		cluster.Spec.LayoutPolicy = LayoutPolicyManual
		cluster.Spec.Storage.Replicas = 9 // ignored in Manual mode
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
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
				Selector:     &metav1.LabelSelector{MatchLabels: map[string]string{testForeignValue: annotationTrue}},
				MinAvailable: ptr.To(intstr.FromInt(7)),
			},
		}
		Expect(k8sClient.Create(ctx, foreign)).To(Succeed())

		Expect(k8sClient.Create(ctx, newCluster(&garagev1beta2.PodDisruptionBudgetConfig{Enabled: true}))).To(Succeed())
		cluster := &garagev1beta2.GarageCluster{}
		Expect(k8sClient.Get(ctx, key, cluster)).To(Succeed())
		Expect(reconciler.reconcileTierPodDisruptionBudget(ctx, cluster, tierStorage)).To(MatchError(ContainSubstring("refusing to mutate PodDisruptionBudget")))

		got := &policyv1.PodDisruptionBudget{}
		Expect(k8sClient.Get(ctx, key, got)).To(Succeed())
		Expect(got.Spec.MinAvailable.IntValue()).To(Equal(7))
		Expect(got.Spec.Selector.MatchLabels).To(HaveKeyWithValue(testForeignValue, annotationTrue))

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
		_ = deleteTestGarageConfigResourcesForCluster(ctx, k8sClient, clusterName)
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
		cluster := &garagev1beta2.GarageCluster{}
		clusterKey := types.NamespacedName{Name: clusterName, Namespace: testNamespace}
		Expect(k8sClient.Get(ctx, clusterKey, cluster)).To(Succeed())
		Expect(reconciler.reconcileTierPodDisruptionBudget(ctx, cluster, tierStorage)).To(Succeed())
		Expect(reconciler.reconcileTierPodDisruptionBudget(ctx, cluster, tierGateway)).To(Succeed())
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

	It("creates a maxUnavailable=1 PDB for Manual gateway members even when the ignored replicas field is zero", func() {
		cluster := newUnifiedCluster(&garagev1beta2.PodDisruptionBudgetConfig{Enabled: true}, 0)
		cluster.Spec.LayoutPolicy = LayoutPolicyManual
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
		driveReconciles()

		pdb := &policyv1.PodDisruptionBudget{}
		Expect(k8sClient.Get(ctx, gwKey, pdb)).To(Succeed())
		Expect(pdb.Spec.MinAvailable).To(BeNil())
		Expect(pdb.Spec.MaxUnavailable).NotTo(BeNil())
		Expect(pdb.Spec.MaxUnavailable.IntValue()).To(Equal(1))
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
