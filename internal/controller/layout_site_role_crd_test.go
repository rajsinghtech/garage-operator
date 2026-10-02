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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// These specs exercise layoutManagement.siteRole against the real generated
// CRD on a real API server (#442): the enum, the absence of any default, and the
// two CEL rules on spec. CRD correctness is the contract; the admission webhook
// repeats the checks but is not installed in envtest.
var _ = Describe("GarageCluster layoutManagement.siteRole CRD validation", func() {
	const (
		followerRule  = "layoutManagement.siteRole: Follower requires at least one remoteClusters entry"
		connectToRule = "layoutManagement.siteRole: Follower is not supported with connectTo"
	)
	var created []client.Object

	AfterEach(func() {
		for _, object := range created {
			_ = k8sClient.Delete(ctx, object)
		}
		created = nil
	})

	remote := []garagev1beta2.RemoteClusterConfig{{
		Name: "writer", Zone: "us-west",
		Connection: garagev1beta2.RemoteClusterConnection{
			AdminAPIEndpoint: "http://writer.example.invalid:3903",
		},
	}}
	storage := func() *garagev1beta2.StorageSpec {
		return &garagev1beta2.StorageSpec{
			Replicas: 1,
			Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
			Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
		}
	}
	v1beta2Cluster := func(name string, mutate func(*garagev1beta2.GarageClusterSpec)) *garagev1beta2.GarageCluster {
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Spec: garagev1beta2.GarageClusterSpec{
				Zone: "us-east", Storage: storage(),
				Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
			},
		}
		mutate(&cluster.Spec)
		return cluster
	}

	It("accepts a Follower with remoteClusters and stores the role verbatim", func() {
		cluster := v1beta2Cluster("siterole-follower-ok", func(s *garagev1beta2.GarageClusterSpec) {
			s.LayoutManagement = &garagev1beta2.LayoutManagementConfig{SiteRole: garagev1beta2.LayoutSiteRoleFollower}
			s.RemoteClusters = remote
		})
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
		created = append(created, cluster)
		stored := &garagev1beta2.GarageCluster{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, stored)).To(Succeed())
		Expect(stored.Spec.LayoutManagement.SiteRole).To(Equal(garagev1beta2.LayoutSiteRoleFollower))
	})

	It("accepts a Writer without remoteClusters", func() {
		cluster := v1beta2Cluster("siterole-writer-ok", func(s *garagev1beta2.GarageClusterSpec) {
			s.LayoutManagement = &garagev1beta2.LayoutManagementConfig{SiteRole: garagev1beta2.LayoutSiteRoleWriter}
		})
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
		created = append(created, cluster)
	})

	It("never defaults siteRole: absent stays absent in storage", func() {
		for _, withLayoutManagement := range []bool{false, true} {
			name := fmt.Sprintf("siterole-absent-%t", withLayoutManagement)
			cluster := v1beta2Cluster(name, func(s *garagev1beta2.GarageClusterSpec) {
				if withLayoutManagement {
					s.LayoutManagement = &garagev1beta2.LayoutManagementConfig{AutoApply: true}
				}
			})
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			created = append(created, cluster)

			raw := &unstructured.Unstructured{}
			raw.SetGroupVersionKind(garagev1beta2.GroupVersion.WithKind("GarageCluster"))
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: testNamespace}, raw)).To(Succeed())
			_, found, err := unstructured.NestedString(raw.Object, "spec", "layoutManagement", "siteRole")
			Expect(err).NotTo(HaveOccurred())
			Expect(found).To(BeFalse(), "the API server must not default spec.layoutManagement.siteRole")
		}
	})

	It("rejects a Follower without remoteClusters", func() {
		cluster := v1beta2Cluster("siterole-follower-noremote", func(s *garagev1beta2.GarageClusterSpec) {
			s.LayoutManagement = &garagev1beta2.LayoutManagementConfig{SiteRole: garagev1beta2.LayoutSiteRoleFollower}
		})
		err := k8sClient.Create(ctx, cluster)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(followerRule))
	})

	It("rejects a Follower with connectTo", func() {
		cluster := v1beta2Cluster("siterole-follower-connectto", func(s *garagev1beta2.GarageClusterSpec) {
			s.LayoutManagement = &garagev1beta2.LayoutManagementConfig{SiteRole: garagev1beta2.LayoutSiteRoleFollower}
			s.RemoteClusters = remote
			s.ConnectTo = &garagev1beta2.ConnectToConfig{ClusterRef: &garagev1beta2.ClusterReference{Name: "other"}}
		})
		err := k8sClient.Create(ctx, cluster)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(connectToRule))
	})

	It("rejects an unknown siteRole value", func() {
		cluster := v1beta2Cluster("siterole-bad-enum", func(s *garagev1beta2.GarageClusterSpec) {
			s.LayoutManagement = &garagev1beta2.LayoutManagementConfig{SiteRole: "Leader"}
		})
		err := k8sClient.Create(ctx, cluster)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("siteRole"))
		Expect(err.Error()).To(ContainSubstring("Unsupported value"))
	})

	It("re-checks the rules on update", func() {
		cluster := v1beta2Cluster("siterole-update", func(s *garagev1beta2.GarageClusterSpec) {
			s.LayoutManagement = &garagev1beta2.LayoutManagementConfig{SiteRole: garagev1beta2.LayoutSiteRoleWriter}
		})
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
		created = append(created, cluster)
		cluster.Spec.LayoutManagement.SiteRole = garagev1beta2.LayoutSiteRoleFollower
		err := k8sClient.Update(ctx, cluster)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(followerRule))

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, cluster)).To(Succeed())
		cluster.Spec.LayoutManagement.SiteRole = garagev1beta2.LayoutSiteRoleFollower
		cluster.Spec.RemoteClusters = remote
		Expect(k8sClient.Update(ctx, cluster)).To(Succeed())
	})

	It("accepts status.layoutWriter and rejects an unknown role through the status subresource", func() {
		cluster := v1beta2Cluster("siterole-status", func(s *garagev1beta2.GarageClusterSpec) {
			s.LayoutManagement = &garagev1beta2.LayoutManagementConfig{SiteRole: garagev1beta2.LayoutSiteRoleWriter}
		})
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
		created = append(created, cluster)
		cluster.Status.LayoutWriter = &garagev1beta2.LayoutWriterStatus{Role: garagev1beta2.LayoutSiteRoleWriter}
		Expect(k8sClient.Status().Update(ctx, cluster)).To(Succeed())
		cluster.Status.LayoutWriter = &garagev1beta2.LayoutWriterStatus{Role: "Leader"}
		Expect(k8sClient.Status().Update(ctx, cluster)).NotTo(Succeed())
	})
})
