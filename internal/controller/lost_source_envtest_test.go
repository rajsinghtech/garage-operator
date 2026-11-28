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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Issue #659 against a real API server: the reporter's fenced lost slot
// (drain + exact ack, StatefulSet at zero, no Pod, stale InLayout=true) must not
// withhold the cluster Admin client, and a role the administrator already
// removed and applied by hand must lead straight to the destination-only proof.
var _ = Describe("acknowledged lost-source recovery (#659)", Ordered, func() {
	var namespace string

	// createLostSourceFixture replays lostSourceFixture into envtest: the API
	// server assigns UIDs, so owner references are rebound and status written
	// through the status subresource, exactly as the controllers would.
	createLostSourceFixture := func(state lostSourceLayoutState) (*garagev1beta2.GarageCluster, *garagev1beta1.GarageNode, *lostSourceGarage) {
		fixtureCluster, fixtureLost, objects := lostSourceFixture(lostSourceTestLostID)
		g := newLostSourceGarage(GinkgoT(), fixtureCluster, state)
		uids := map[types.UID]types.UID{}
		var cluster *garagev1beta2.GarageCluster
		var lost *garagev1beta1.GarageNode
		for _, object := range objects {
			object = object.DeepCopyObject().(client.Object)
			object.SetNamespace(namespace)
			oldUID := object.GetUID()
			object.SetUID("")
			object.SetResourceVersion("")
			refs := object.GetOwnerReferences()
			for i := range refs {
				refs[i].UID = uids[refs[i].UID]
			}
			object.SetOwnerReferences(refs)
			var status func() error
			switch typed := object.(type) {
			case *garagev1beta2.GarageCluster:
				saved := typed.Status
				typed.Spec.Admin.BindPort = fixtureCluster.Spec.Admin.BindPort
				status = func() error { typed.Status = saved; return k8sClient.Status().Update(ctx, typed) }
				cluster = typed
			case *garagev1beta1.GarageNode:
				saved := typed.Status
				status = func() error { typed.Status = saved; return k8sClient.Status().Update(ctx, typed) }
				if typed.Name == fixtureLost.Name {
					lost = typed
				}
			case *appsv1.StatefulSet:
				labels := map[string]string{labelCluster: fixtureCluster.Name, "slot": typed.Name}
				typed.Spec.Selector = &metav1.LabelSelector{MatchLabels: labels}
				typed.Spec.Template = corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: labels},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: defaultAppName, Image: "dxflrs/garage:v2.5.0"}}},
				}
			case *corev1.Secret:
				// The operator token Secret and token names derive from the
				// cluster UID, which only the API server assigns.
				if _, operatorToken := typed.Labels[labelOperatorAdminToken]; operatorToken {
					typed.Name = operatorAdminTokenSecretName(cluster)
					typed.Annotations[annotationOperatorAdminTokenName] = operatorAdminTokenName(cluster)
				}
			case *corev1.Pod:
				saved := typed.Status
				saved.Conditions[0].LastTransitionTime = metav1.Now()
				status = func() error { typed.Status = saved; return k8sClient.Status().Update(ctx, typed) }
			}
			Expect(k8sClient.Create(ctx, object)).To(Succeed(), "creating %T %s", object, object.GetName())
			uids[oldUID] = object.GetUID()
			if object == client.Object(cluster) {
				*fixtureCluster = *cluster.DeepCopy() // the fake Garage names the token from it
			}
			if status != nil {
				Expect(status()).To(Succeed(), "writing status of %T %s", object, object.GetName())
			}
		}
		Expect(cluster).NotTo(BeNil())
		Expect(lost).NotTo(BeNil())
		return cluster, lost, g
	}

	BeforeEach(func() {
		namespace = fmt.Sprintf("lost-source-659-%d", time.Now().UnixNano())
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(context.Background(), ns) })
	})

	newReconciler := func() *GarageNodeReconciler {
		return &GarageNodeReconciler{
			Client: k8sClient, APIReader: k8sClient, Scheme: k8sClient.Scheme(),
			LayoutMutations: NewLayoutMutationCoordinator(),
			clusterHealthGetter: func(context.Context, *garage.Client) (*garage.ClusterHealth, error) {
				return &garage.ClusterHealth{
					Status: healthStatusHealthy, StorageNodes: 3, StorageNodesUp: 3,
					Partitions: 256, PartitionsQuorum: 256, PartitionsAllOK: 256,
				}, nil
			},
			blockResyncObservationGetter: func(context.Context, *garage.Client) (*blockResyncObservation, error) {
				return nil, fmt.Errorf("%w: block-resync proof intentionally pending", errLayoutMutationPending)
			},
		}
	}

	It("reaches a healthy peer and records the destination-only proof for a role removed by hand", func() {
		cluster, lost, g := createLostSourceFixture(lostRoleRemovedByHand)

		garageClient, err := GetGarageClient(ctx, k8sClient, cluster, "cluster.local")
		Expect(err).NotTo(HaveOccurred(), "the fenced lost slot must not withhold the cluster Admin client")
		status, err := garageClient.GetClusterStatus(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(status.LayoutVersion).To(Equal(uint64(3)))

		_, _, err = newReconciler().prepareGarageNodeDrain(ctx, lost, cluster, cluster)
		Expect(err).To(MatchError(ContainSubstring("block-resync proof intentionally pending")))
		Expect(err.Error()).NotTo(ContainSubstring("must desire exactly one Pod"))
		Expect(g.layoutWrites()).To(BeEmpty(), "the operator must not touch a layout the administrator already applied")

		stored := &garagev1beta2.GarageCluster{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), stored)).To(Succeed())
		proof := clusterStorageDrainProof(stored.Status.StorageDrain)
		Expect(proof).NotTo(BeNil())
		Expect(proof.RemovedStorageNodeIDs).To(Equal([]string{lostSourceTestLostID}))
		Expect(storageDrainUnavailableSourceIncludes(proof, lostSourceTestLostID)).To(BeTrue())

		sts := &appsv1.StatefulSet{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: lost.Name}, sts)).To(Succeed())
		Expect(*sts.Spec.Replicas).To(BeZero(), "the lost slot stays fenced")
	})

	It("names the exact remaining step for a hand-staged removal and never applies it", func() {
		cluster, lost, g := createLostSourceFixture(lostRoleStagedRemoved)
		_, _, err := newReconciler().prepareGarageNodeDrain(ctx, lost, cluster, cluster)
		Expect(err).To(MatchError(ContainSubstring("staged but not applied")))
		Expect(err.Error()).To(ContainSubstring("garage layout apply --version 3"))
		Expect(g.layoutWrites()).To(BeEmpty())
		stored := &garagev1beta2.GarageCluster{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cluster), stored)).To(Succeed())
		Expect(stored.Status.StorageDrain).To(BeNil())
	})
})
