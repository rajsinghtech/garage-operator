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
	"fmt"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// legacyGarageCluster is the deprecated v1beta1 GarageCluster, which these specs
// deliberately exercise: its OpenAPI schema is still served.
type legacyGarageCluster = garagev1beta1.GarageCluster //nolint:staticcheck // schema under test

// These specs exercise the generated CRD schema (patterns, lengths, CEL) with
// no admission webhook in front of it. They prove the API server itself
// enforces the volumeAttributesClassName contract, and, because the CRDs only
// install when every CEL rule fits the per-rule cost budget, that the new rules
// are cheap enough to ship.
var _ = Describe("volumeAttributesClassName CRD schema", func() {
	const ns = testNamespace
	var seq int

	uniq := func(prefix string) string {
		seq++
		return fmt.Sprintf("%s-%d", prefix, seq)
	}
	qty := func(v string) *resource.Quantity { q := resource.MustParse(v); return &q }

	cleanup := func(obj client.Object) {
		DeferCleanup(func() {
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj); err == nil {
				obj.SetFinalizers(nil)
				_ = k8sClient.Update(ctx, obj)
				_ = k8sClient.Delete(ctx, obj)
			}
		})
	}

	cluster := func(mutate func(*garagev1beta2.GarageCluster)) *garagev1beta2.GarageCluster {
		c := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: uniq("vac-schema"), Namespace: ns},
			Spec: garagev1beta2.GarageClusterSpec{
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{Size: qty("1Gi")},
					Data:     &garagev1beta2.VolumeConfig{Size: qty("10Gi")},
				},
				Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
			},
		}
		mutate(c)
		return c
	}

	Context("v1beta2 GarageCluster", func() {
		DescribeTable("accepts valid DNS-subdomain class names on every carrier",
			func(name string) {
				c := cluster(func(c *garagev1beta2.GarageCluster) {
					c.Spec.Storage.Metadata.VolumeAttributesClassName = ptr.To(name)
					c.Spec.Storage.Data.VolumeAttributesClassName = ptr.To(name)
				})
				Expect(k8sClient.Create(ctx, c)).To(Succeed())
				cleanup(c)
				Expect(*c.Spec.Storage.Data.VolumeAttributesClassName).To(Equal(name))
			},
			Entry("simple", "gold"),
			Entry("dotted", "fast.tier.example.com"),
			Entry("dashed with digits", "gold-2"),
			Entry("253 characters", func() string {
				label := "a23456789012345678901234567890123456789012345678901234567890123"
				return label + "." + label + "." + label + "." + label[:61]
			}()),
		)

		It("accepts the class on data paths and on a gateway tier", func() {
			c := cluster(func(c *garagev1beta2.GarageCluster) {
				c.Spec.Storage.Data = &garagev1beta2.VolumeConfig{Paths: []garagev1beta2.DataPath{{
					Path: "/data/fast", Capacity: qty("10Gi"),
					Volume: &garagev1beta2.DataPathVolumeConfig{Size: qty("10Gi"), VolumeAttributesClassName: ptr.To("fast")},
				}}}
				c.Spec.Gateway = &garagev1beta2.GatewaySpec{Replicas: 1, Metadata: &garagev1beta2.VolumeConfig{
					Size: qty("1Gi"), VolumeAttributesClassName: ptr.To("gw"),
				}}
			})
			Expect(k8sClient.Create(ctx, c)).To(Succeed())
			cleanup(c)
		})

		DescribeTable("rejects invalid class names",
			func(name, want string) {
				c := cluster(func(c *garagev1beta2.GarageCluster) {
					c.Spec.Storage.Data.VolumeAttributesClassName = ptr.To(name)
				})
				err := k8sClient.Create(ctx, c)
				Expect(err).To(HaveOccurred())
				Expect(errors.IsInvalid(err)).To(BeTrue(), "got %v", err)
				Expect(err.Error()).To(ContainSubstring(want))
			},
			Entry("empty", "", "volumeAttributesClassName"),
			Entry("uppercase", "Gold", "volumeAttributesClassName"),
			Entry("underscore", "gold_tier", "volumeAttributesClassName"),
			Entry("leading dash", "-gold", "volumeAttributesClassName"),
			Entry("trailing dot", "gold.", "volumeAttributesClassName"),
			Entry("254 characters", func() string {
				label := "a23456789012345678901234567890123456789012345678901234567890123"
				return label + "." + label + "." + label + "." + label[:62]
			}(), "volumeAttributesClassName"),
		)

		It("rejects a class on an EmptyDir volume", func() {
			c := cluster(func(c *garagev1beta2.GarageCluster) {
				c.Spec.Storage.Metadata.Type = garagev1beta2.VolumeTypeEmptyDir
				c.Spec.Storage.Metadata.VolumeAttributesClassName = ptr.To("gold")
			})
			err := k8sClient.Create(ctx, c)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("volumeAttributesClassName"))
		})

		It("rejects a class on an EmptyDir data path volume", func() {
			c := cluster(func(c *garagev1beta2.GarageCluster) {
				c.Spec.Storage.Data = &garagev1beta2.VolumeConfig{Paths: []garagev1beta2.DataPath{{
					Path: "/data/scratch", Capacity: qty("10Gi"),
					Volume: &garagev1beta2.DataPathVolumeConfig{
						Type: garagev1beta2.VolumeTypeEmptyDir, Size: qty("10Gi"), VolumeAttributesClassName: ptr.To("gold"),
					},
				}}}
			})
			err := k8sClient.Create(ctx, c)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("volumeAttributesClassName"))
		})

		It("leaves the field absent when unset (no default)", func() {
			c := cluster(func(*garagev1beta2.GarageCluster) {})
			Expect(k8sClient.Create(ctx, c)).To(Succeed())
			cleanup(c)
			stored := &garagev1beta2.GarageCluster{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(c), stored)).To(Succeed())
			Expect(stored.Spec.Storage.Metadata.VolumeAttributesClassName).To(BeNil())
			Expect(stored.Spec.Storage.Data.VolumeAttributesClassName).To(BeNil())
		})

		It("lets a class be added, changed and removed at the schema level (the webhook owns the unset rule)", func() {
			c := cluster(func(*garagev1beta2.GarageCluster) {})
			Expect(k8sClient.Create(ctx, c)).To(Succeed())
			cleanup(c)
			for _, class := range []*string{ptr.To("gold"), ptr.To("silver"), nil} {
				stored := &garagev1beta2.GarageCluster{}
				Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(c), stored)).To(Succeed())
				stored.Spec.Storage.Data.VolumeAttributesClassName = class
				Expect(k8sClient.Update(ctx, stored)).To(Succeed())
			}
		})
	})

	Context("v1beta1 GarageNode", func() {
		node := func(mutate func(*garagev1beta1.GarageNode)) *garagev1beta1.GarageNode {
			n := &garagev1beta1.GarageNode{
				ObjectMeta: metav1.ObjectMeta{Name: uniq("vac-node"), Namespace: ns},
				Spec: garagev1beta1.GarageNodeSpec{
					ClusterRef: garagev1beta1.ClusterReference{Name: "some-cluster"},
					Zone:       "dc1",
					Capacity:   qty("10Gi"),
					Storage: &garagev1beta1.NodeStorageConfig{
						Metadata: &garagev1beta1.NodeVolumeConfig{Size: qty("1Gi")},
						Data:     &garagev1beta1.NodeVolumeConfig{Size: qty("10Gi")},
					},
				},
			}
			mutate(n)
			return n
		}

		It("accepts a valid class on metadata, data and dataPaths", func() {
			n := node(func(n *garagev1beta1.GarageNode) {
				n.Spec.Storage.Metadata.VolumeAttributesClassName = ptr.To("gold")
				n.Spec.Storage.Data = nil
				n.Spec.Storage.DataPaths = []garagev1beta1.NodeVolumeConfig{
					{Size: qty("5Gi"), VolumeAttributesClassName: ptr.To("fast.tier")},
					{Size: qty("5Gi")},
				}
			})
			Expect(k8sClient.Create(ctx, n)).To(Succeed())
			cleanup(n)
		})

		DescribeTable("rejects invalid class names",
			func(name string) {
				n := node(func(n *garagev1beta1.GarageNode) { n.Spec.Storage.Data.VolumeAttributesClassName = ptr.To(name) })
				err := k8sClient.Create(ctx, n)
				Expect(err).To(HaveOccurred())
				Expect(errors.IsInvalid(err)).To(BeTrue(), "got %v", err)
			},
			Entry("empty", ""),
			Entry("uppercase", "Gold"),
			Entry("underscore", "a_b"),
		)

		It("rejects a class on an EmptyDir volume", func() {
			n := node(func(n *garagev1beta1.GarageNode) {
				n.Spec.Storage.Metadata.Type = garagev1beta1.VolumeTypeEmptyDir
				n.Spec.Storage.Metadata.VolumeAttributesClassName = ptr.To("gold")
			})
			err := k8sClient.Create(ctx, n)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("volumeAttributesClassName"))
		})

		It("rejects a class on an existingClaim volume", func() {
			n := node(func(n *garagev1beta1.GarageNode) {
				n.Spec.Storage.Metadata = &garagev1beta1.NodeVolumeConfig{
					ExistingClaim: "adopted", VolumeAttributesClassName: ptr.To("gold"),
				}
			})
			err := k8sClient.Create(ctx, n)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("volumeAttributesClassName"))
		})

		It("still accepts an existingClaim volume without a class", func() {
			n := node(func(n *garagev1beta1.GarageNode) {
				n.Spec.Storage.Metadata = &garagev1beta1.NodeVolumeConfig{ExistingClaim: "adopted"}
			})
			Expect(k8sClient.Create(ctx, n)).To(Succeed())
			cleanup(n)
		})
	})

	// Kubernetes' own PVC validation is what makes in-place patching work, so
	// the assumptions the controller relies on are asserted against the real API
	// server rather than taken on faith.
	Context("PersistentVolumeClaim API semantics", func() {
		newPVC := func(class *string) *corev1.PersistentVolumeClaim {
			return &corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{Name: uniq("vac-pvc"), Namespace: ns},
				Spec: corev1.PersistentVolumeClaimSpec{
					AccessModes:               []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					Resources:                 corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")}},
					VolumeAttributesClassName: class,
				},
			}
		}
		patchClass := func(pvc *corev1.PersistentVolumeClaim, class *string) error {
			patch := client.MergeFrom(pvc.DeepCopy())
			pvc.Spec.VolumeAttributesClassName = class
			return k8sClient.Patch(ctx, pvc, patch)
		}

		It("accepts creation with a class that does not exist yet", func() {
			pvc := newPVC(ptr.To("not-created-yet"))
			Expect(k8sClient.Create(ctx, pvc)).To(Succeed())
			cleanup(pvc)
			Expect(*pvc.Spec.VolumeAttributesClassName).To(Equal("not-created-yet"))
		})

		It("forbids changing the class while the claim is Pending and allows it once Bound", func() {
			pvc := newPVC(nil)
			Expect(k8sClient.Create(ctx, pvc)).To(Succeed())
			cleanup(pvc)

			err := patchClass(pvc.DeepCopy(), ptr.To("gold"))
			Expect(err).To(HaveOccurred(), "Kubernetes must forbid a class change on a Pending claim")
			Expect(errors.IsInvalid(err) || errors.IsForbidden(err)).To(BeTrue(), "got %v", err)

			// Emulate the PV controller: bind the claim.
			fresh := &corev1.PersistentVolumeClaim{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(pvc), fresh)).To(Succeed())
			fresh.Spec.VolumeName = "pv-" + fresh.Name
			Expect(k8sClient.Update(ctx, fresh)).To(Succeed())
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(pvc), fresh)).To(Succeed())
			fresh.Status.Phase = corev1.ClaimBound
			Expect(k8sClient.Status().Update(ctx, fresh)).To(Succeed())

			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(pvc), fresh)).To(Succeed())
			Expect(patchClass(fresh, ptr.To("gold"))).To(Succeed())
			Expect(*fresh.Spec.VolumeAttributesClassName).To(Equal("gold"))

			// The one-field merge patch leaves every other field untouched.
			Expect(fresh.Spec.Resources.Requests[corev1.ResourceStorage]).To(Equal(resource.MustParse("1Gi")))
			Expect(fresh.Spec.VolumeName).To(Equal("pv-" + pvc.Name))

			// Changing again is also fine; the API server even lets the class be
			// removed from a bound claim, which is why the operator's webhook
			// rejects unsetting a configured value.
			Expect(patchClass(fresh, ptr.To("silver"))).To(Succeed())
			Expect(patchClass(fresh, nil)).To(Succeed())
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: pvc.Name, Namespace: ns}, fresh)).To(Succeed())
			Expect(fresh.Spec.VolumeAttributesClassName).To(BeNil())
		})
	})
})

// The v1beta1 GarageCluster schema is served alongside v1beta2 behind a
// conversion webhook, which this suite has no way to run. To validate the
// v1beta1 OpenAPI schema (pattern, length and CEL, including the cost budget)
// in a real API server, start a second one that serves only v1beta1 with no
// conversion.
var _ = Describe("volumeAttributesClassName v1beta1 GarageCluster schema", Ordered, func() {
	var (
		env *envtest.Environment
		c   client.Client
	)

	BeforeAll(func() {
		options := envtest.CRDInstallOptions{Paths: []string{filepath.Join("..", "..", "config", "crd", "bases")}}
		Expect(envtest.ReadCRDFiles(&options)).To(Succeed())
		var crds []*apiextensionsv1.CustomResourceDefinition
		for _, crd := range options.CRDs {
			if crd.Spec.Names.Kind != "GarageCluster" {
				continue
			}
			var versions []apiextensionsv1.CustomResourceDefinitionVersion
			for _, v := range crd.Spec.Versions {
				if v.Name == "v1beta1" {
					v.Served, v.Storage = true, true
					versions = append(versions, v)
				}
			}
			Expect(versions).To(HaveLen(1))
			crd.Spec.Versions = versions
			crd.Spec.Conversion = nil
			crds = append(crds, crd)
		}
		Expect(crds).To(HaveLen(1))

		env = &envtest.Environment{CRDs: crds, ErrorIfCRDPathMissing: true}
		if dir := getEnvTestBinaryDir(); dir != "" {
			env.BinaryAssetsDirectory = dir
		}
		restCfg, err := env.Start()
		Expect(err).NotTo(HaveOccurred())
		c, err = client.New(restCfg, client.Options{Scheme: scheme.Scheme})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		if env != nil {
			Expect(env.Stop()).To(Succeed())
		}
	})

	var seq int
	v1beta1Cluster := func(mutate func(*legacyGarageCluster)) *legacyGarageCluster {
		seq++
		q := func(v string) *resource.Quantity { r := resource.MustParse(v); return &r }
		cl := &legacyGarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("vac-v1beta1-%d", seq), Namespace: "default"},
			Spec: garagev1beta1.GarageClusterSpec{
				Replicas: 1,
				Storage: garagev1beta1.StorageConfig{
					Metadata: &garagev1beta1.VolumeConfig{Size: q("1Gi")},
					Data:     &garagev1beta1.VolumeConfig{Size: q("10Gi")},
				},
				Replication: &garagev1beta1.ReplicationConfig{Factor: 1},
			},
		}
		mutate(cl)
		return cl
	}

	It("accepts valid names on metadata, data and data paths", func() {
		q := resource.MustParse("5Gi")
		cl := v1beta1Cluster(func(cl *legacyGarageCluster) {
			cl.Spec.Storage.Metadata.VolumeAttributesClassName = ptr.To("gold")
			cl.Spec.Storage.Data = &garagev1beta1.VolumeConfig{Paths: []garagev1beta1.DataPath{{
				Path: "/data/a", Capacity: &q,
				Volume: &garagev1beta1.DataPathVolumeConfig{Size: &q, VolumeAttributesClassName: ptr.To("fast.tier")},
			}}}
		})
		Expect(c.Create(ctx, cl)).To(Succeed())
		stored := &legacyGarageCluster{}
		Expect(c.Get(ctx, client.ObjectKeyFromObject(cl), stored)).To(Succeed())
		Expect(*stored.Spec.Storage.Metadata.VolumeAttributesClassName).To(Equal("gold"))
		Expect(*stored.Spec.Storage.Data.Paths[0].Volume.VolumeAttributesClassName).To(Equal("fast.tier"))
	})

	DescribeTable("rejects invalid names",
		func(name string) {
			cl := v1beta1Cluster(func(cl *legacyGarageCluster) { cl.Spec.Storage.Data.VolumeAttributesClassName = ptr.To(name) })
			err := c.Create(ctx, cl)
			Expect(err).To(HaveOccurred())
			Expect(errors.IsInvalid(err)).To(BeTrue(), "got %v", err)
		},
		Entry("empty", ""),
		Entry("uppercase", "Gold"),
		Entry("underscore", "a_b"),
		Entry("trailing dash", "gold-"),
	)

	It("rejects a class on an EmptyDir volume", func() {
		cl := v1beta1Cluster(func(cl *legacyGarageCluster) {
			cl.Spec.Storage.Metadata.Type = garagev1beta1.VolumeTypeEmptyDir
			cl.Spec.Storage.Metadata.VolumeAttributesClassName = ptr.To("gold")
		})
		err := c.Create(ctx, cl)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("volumeAttributesClassName"))
	})
})
