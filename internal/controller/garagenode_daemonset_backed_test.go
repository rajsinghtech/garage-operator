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
	stderrors "errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// DaemonSet-backed GarageNodes do not own a per-node StatefulSet: pods come
// from a named, cluster-owned node-local pool, and the GarageNode only manages the
// layout role for one Kubernetes Node. These tests exercise the
// GarageNodeReconciler directly.
const (
	dsWorker1       = "worker-1"
	dsWorker2       = "worker-2"
	dsWorker2PodIP  = "10.0.0.12"
	dsPool          = "local"
	dsControllerUID = types.UID("test-daemonset-uid")
)

var _ = Describe("GarageNode DaemonSet-backed mode", func() {
	const (
		clusterName = "ds-backed-cluster"
		nodeName    = "ds-backed-node"
	)

	nodeNN := types.NamespacedName{Name: nodeName, Namespace: testNamespace}

	AfterEach(func() {
		n := &garagev1beta1.GarageNode{}
		if err := k8sClient.Get(ctx, nodeNN, n); err == nil {
			n.Finalizers = nil
			_ = k8sClient.Update(ctx, n)
			_ = k8sClient.Delete(ctx, n)
		}
		c := &garagev1beta2.GarageCluster{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: clusterName, Namespace: testNamespace}, c); err == nil {
			c.Finalizers = nil
			_ = k8sClient.Update(ctx, c)
			_ = k8sClient.Delete(ctx, c)
		}
		_ = k8sClient.Delete(ctx, &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: testNamespace}})
	})

	It("does not create a StatefulSet for a DaemonSet-backed GarageNode", func() {
		By("creating a minimal cluster for the clusterRef (never reconciled)")
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: testNamespace},
			Spec: garagev1beta2.GarageClusterSpec{
				LayoutPolicy: LayoutPolicyManual,
				Replication:  &garagev1beta2.ReplicationConfig{Factor: 1},
				Storage: &garagev1beta2.StorageSpec{
					Replicas: 1,
					Metadata: &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("1Gi"))},
					Data:     &garagev1beta2.VolumeConfig{Size: ptrQuantity(resource.MustParse("10Gi"))},
				},
			},
		}
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

		By("creating a DaemonSet-backed GarageNode pinned to a Kubernetes node")
		capacity := resource.MustParse("100Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: testNamespace},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef:         garagev1beta1.ClusterReference{Name: clusterName},
				Zone:               testNodeZone,
				ZoneFrom:           &garagev1beta1.ZoneSource{NodeLabel: corev1.LabelTopologyZone},
				Capacity:           &capacity,
				Backing:            garagev1beta1.NodeBackingNodeLocalPool,
				KubernetesNodeName: dsWorker1,
				NodeLocalPoolName:  dsPool,
				// A storage config a StatefulSet-backed node would use — present to
				// prove the DaemonSet backing alone suppresses the StatefulSet.
				Storage: &garagev1beta1.NodeStorageConfig{
					Data: &garagev1beta1.NodeVolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
				},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())

		// Node-local pool backing and zoneFrom both require the cluster-scoped
		// install contract in production; model that valid controller shape.
		r := &GarageNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme(), ClusterScoped: true}
		req := reconcile.Request{NamespacedName: nodeNN}

		By("first reconcile adds the finalizer and requeues")
		res, err := r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(reconcile.Result{Requeue: true}))

		By("second reconcile runs the workload phase; the Garage admin API is unreachable in envtest, which is fine — workload objects are created before that point")
		_, _ = r.Reconcile(ctx, req)

		By("verifying no StatefulSet was created for the node")
		sts := &appsv1.StatefulSet{}
		getErr := k8sClient.Get(ctx, nodeNN, sts)
		Expect(apierrors.IsNotFound(getErr)).To(BeTrue(),
			"expected no StatefulSet for a DaemonSet-backed GarageNode, got err=%v", getErr)
	})
})

// node_id discovery for DaemonSet-backed nodes: the pod is not named
// <node>-0 (that's the StatefulSet convention) — it is whichever DaemonSet
// pod is scheduled on spec.kubernetesNodeName. Uses the fake in-memory Garage
// layout server + a fake client holding the pods, mirroring the stale-role
// tests.
var _ = Describe("GarageNode DaemonSet-backed node_id discovery", func() {
	const (
		ns        = "ds-discovery-ns"
		dsCluster = "ds-disc-cluster"
		idWorker1 = "1111111111111111111111111111111111111111111111111111111111111111"
		idWorker2 = "2222222222222222222222222222222222222222222222222222222222222222"
	)

	var (
		bctx   context.Context
		scheme *runtime.Scheme
	)

	BeforeEach(func() {
		bctx = context.Background()
		scheme = runtime.NewScheme()
		Expect(appsv1.AddToScheme(scheme)).To(Succeed())
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(garagev1beta1.AddToScheme(scheme)).To(Succeed())
		Expect(garagev1beta2.AddToScheme(scheme)).To(Succeed())
	})

	mkClusterAndDaemonSet := func() (*garagev1beta2.GarageCluster, *appsv1.DaemonSet) {
		controller := true
		cluster := &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      dsCluster,
				Namespace: ns,
				UID:       types.UID("test-cluster-uid"),
			},
		}
		daemonSet := &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      storageDaemonSetName(cluster, dsPool),
				Namespace: ns,
				UID:       dsControllerUID,
				Labels: map[string]string{
					labelCluster:       dsCluster,
					labelTier:          tierStorage,
					labelNodeLocalPool: dsPool,
				},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: garagev1beta2.GroupVersion.String(),
					Kind:       testGarageClusterKind,
					Name:       cluster.Name,
					UID:        cluster.UID,
					Controller: &controller,
				}},
			},
		}
		return cluster, daemonSet
	}

	// mkDSPod builds a pod as the cluster-owned storage DaemonSet would
	// produce it. nodeID is deliberately only a user-forgeable annotation;
	// production identity discovery must ignore it and trust Garage's API for
	// the exact ownership-proven Pod IP.
	mkDSPod := func(name, k8sNodeName, nodeID string) *corev1.Pod {
		podIP := testStoragePodIP
		if k8sNodeName == dsWorker2 {
			podIP = dsWorker2PodIP
		}
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
				UID:       types.UID(name + "-uid"),
				Labels: map[string]string{
					labelCluster:       dsCluster,
					labelTier:          tierStorage,
					labelNodeLocalPool: dsPool,
				},
				Annotations: map[string]string{"garage.rajsingh.info/node-id": nodeID},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: appsv1.SchemeGroupVersion.String(),
					Kind:       daemonSetKind,
					Name:       dsCluster + "-storage-" + dsPool,
					UID:        dsControllerUID,
					Controller: ptr.To(true),
				}},
			},
			Spec: corev1.PodSpec{
				NodeName:   k8sNodeName,
				Containers: []corev1.Container{{Name: fmGarageContainer, Image: daemonSetTestGarageImage}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: podIP},
		}
	}

	exactPoolIdentity := func(
		_ context.Context,
		_ *garagev1beta1.GarageNode,
		_ *garagev1beta2.GarageCluster,
		podIPs []string,
	) (string, error) {
		if len(podIPs) == 0 {
			return "", fmt.Errorf("managed pod has no IPs")
		}
		switch podIPs[0] {
		case testStoragePodIP:
			return idWorker1, nil
		case dsWorker2PodIP:
			return idWorker2, nil
		default:
			return "", fmt.Errorf("unexpected managed pod IP %q", podIPs[0])
		}
	}

	It("discovers the node_id from the DaemonSet pod on spec.kubernetesNodeName and stages that role only", func() {
		fakeLayout := newFakeGarageLayout()
		fakeLayout.statusNodes = []garage.NodeInfo{
			{ID: idWorker1, Address: ptr.To(testStoragePodIP + ":3901"), IsUp: true},
			{ID: idWorker2, Address: ptr.To(dsWorker2PodIP + ":3901"), IsUp: true},
		}
		srv := fakeLayout.server()
		defer srv.Close()
		gcl := garage.NewClient(srv.URL, "test-token")

		cluster, daemonSet := mkClusterAndDaemonSet()
		forgedPod := mkDSPod("ds-disc-cluster-storage-forged", dsWorker1, idWorker2)
		forgedPod.OwnerReferences[0].UID = types.UID("forged-daemonset-uid")
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
			cluster,
			daemonSet,
			forgedPod,
			mkDSPod("ds-disc-cluster-storage-abcde", dsWorker1, idWorker2),
			mkDSPod("ds-disc-cluster-storage-fghij", dsWorker2, idWorker2),
		).WithStatusSubresource(&garagev1beta1.GarageNode{}).Build()

		capacity := resource.MustParse("100Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "ds-node-worker-1", Namespace: ns},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef:         garagev1beta1.ClusterReference{Name: dsCluster},
				Zone:               testNodeZone,
				Capacity:           &capacity,
				Backing:            garagev1beta1.NodeBackingNodeLocalPool,
				KubernetesNodeName: dsWorker1,
				NodeLocalPoolName:  dsPool,
				Network:            &garagev1beta1.NodeNetworkConfig{RPCPublicAddr: "worker-1.storage.example.net:3901"},
			},
		}
		Expect(fc.Create(bctx, node)).To(Succeed())
		r := &GarageNodeReconciler{
			Client: fc, Scheme: scheme, nodeLocalPoolRecoveryNodeIDGetter: exactPoolIdentity,
		}
		Expect(stderrors.Is(r.reconcileNode(bctx, node, cluster, gcl, cluster), errLayoutMutationPending)).To(BeTrue())
		Expect(stderrors.Is(r.reconcileNode(bctx, node, cluster, gcl, cluster), errLayoutMutationPending)).To(BeTrue())
		Expect(r.reconcileNode(bctx, node, cluster, gcl, cluster)).To(Succeed())

		Expect(node.Status.NodeID).To(Equal(idWorker1), "must pick the pod scheduled on worker-1")
		Expect(fakeLayout.hasRole(idWorker1)).To(BeTrue(), "worker-1's identity must get the layout role")
		Expect(fakeLayout.hasRole(idWorker2)).To(BeFalse(), "the pod on the other K8s node must not be touched")
		fakeLayout.mu.Lock()
		role := fakeLayout.roles[idWorker1]
		fakeLayout.mu.Unlock()
		Expect(role.Tags).To(ContainElement(nodeRPCAddressTagPrefix+"worker-1.storage.example.net:3901"),
			"the identity-specific address must be replicated for federation reconnect")
	})

	It("discovers the exact DaemonSet process identity when the annotation is absent", func() {
		fakeLayout := newFakeGarageLayout()
		fakeLayout.statusNodes = []garage.NodeInfo{
			{ID: idWorker1, Address: ptr.To("10.0.0.11:3901"), IsUp: true},
			{ID: idWorker2, Address: ptr.To(dsWorker2PodIP + ":3901"), IsUp: true},
		}
		srv := fakeLayout.server()
		defer srv.Close()
		gcl := garage.NewClient(srv.URL, "test-token")

		// Pods carry no node-id annotation. The exact Pod's self endpoint remains
		// authoritative; cluster status is only a connectivity observation.
		pod1 := mkDSPod("ds-disc-cluster-storage-abcde", dsWorker1, "")
		pod1.Annotations = nil
		pod1.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: testStoragePodIP}
		pod2 := mkDSPod("ds-disc-cluster-storage-fghij", dsWorker2, "")
		pod2.Annotations = nil
		pod2.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: dsWorker2PodIP}

		cluster, daemonSet := mkClusterAndDaemonSet()
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, daemonSet, pod1, pod2).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).Build()

		capacity := resource.MustParse("100Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "ds-node-worker-1", Namespace: ns},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef:         garagev1beta1.ClusterReference{Name: dsCluster},
				Zone:               testNodeZone,
				Capacity:           &capacity,
				Backing:            garagev1beta1.NodeBackingNodeLocalPool,
				KubernetesNodeName: dsWorker1,
				NodeLocalPoolName:  dsPool,
			},
		}
		Expect(fc.Create(bctx, node)).To(Succeed())
		r := &GarageNodeReconciler{
			Client: fc, Scheme: scheme, nodeLocalPoolRecoveryNodeIDGetter: exactPoolIdentity,
		}
		Expect(stderrors.Is(r.reconcileNode(bctx, node, cluster, gcl, cluster), errLayoutMutationPending)).To(BeTrue())
		Expect(stderrors.Is(r.reconcileNode(bctx, node, cluster, gcl, cluster), errLayoutMutationPending)).To(BeTrue())
		Expect(r.reconcileNode(bctx, node, cluster, gcl, cluster)).To(Succeed())

		Expect(node.Status.NodeID).To(Equal(idWorker1), "must resolve worker-1's exact process identity")
		Expect(fakeLayout.hasRole(idWorker1)).To(BeTrue())
		Expect(fakeLayout.hasRole(idWorker2)).To(BeFalse())
	})

	It("repairs the per-Pod node routing label from the GarageNode reconcile backstop", func() {
		cluster, daemonSet := mkClusterAndDaemonSet()
		pod := mkDSPod("ds-disc-cluster-storage-label-repair", dsWorker1, "")
		pod.Annotations = nil
		pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: testStoragePodIP}
		capacity := resource.MustParse("100Gi")
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{Name: "ds-node-label-repair", Namespace: ns},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef:         garagev1beta1.ClusterReference{Name: dsCluster},
				Zone:               testNodeZone,
				Capacity:           &capacity,
				Backing:            garagev1beta1.NodeBackingNodeLocalPool,
				KubernetesNodeName: dsWorker1,
				NodeLocalPoolName:  dsPool,
			},
		}
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, daemonSet, pod).Build()
		r := &GarageNodeReconciler{Client: fc, Scheme: scheme}

		_, err := r.managedPodForNode(bctx, node, cluster)
		Expect(err).NotTo(HaveOccurred())

		got := &corev1.Pod{}
		Expect(fc.Get(bctx, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, got)).To(Succeed())
		Expect(got.Labels).To(HaveKeyWithValue(labelKubernetesNode, dsWorker1))
		Expect(got.Annotations).To(HaveKeyWithValue(annotationKubernetesNode, dsWorker1))
	})

	It("accepts a cold-recovery identity only after direct discovery and an exact committed role proof", func() {
		capacity := resource.MustParse("100Gi")
		cluster, daemonSet := mkClusterAndDaemonSet()
		role := garage.LayoutNodeRole{
			ID:       idWorker1,
			Zone:     testNodeZone,
			Capacity: ptr.To(uint64(capacity.Value())),
			Tags: []string{
				fmt.Sprintf("cluster:%s/%s", cluster.Name, cluster.Namespace),
				nodeClusterUIDTagPrefix + string(cluster.UID),
				"tier:" + tierStorage,
				nodeLocalPoolLayoutTagPrefix + dsPool,
				"kubernetes-node:" + dsWorker1,
			},
		}
		fakeLayout := newFakeGarageLayout(role)
		fakeLayout.statusNodes = []garage.NodeInfo{{
			ID: idWorker1, Address: ptr.To("10.0.0.11:3901"), IsUp: true,
		}}
		srv := fakeLayout.server()
		defer srv.Close()
		gcl := garage.NewClient(srv.URL, "test-token")

		pod := mkDSPod("ds-disc-cluster-storage-recovery", dsWorker1, "")
		pod.Annotations = nil
		pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: testStoragePodIP}
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ds-node-recovery",
				Namespace: ns,
				Annotations: map[string]string{
					garagev1beta1.AnnotationNodeLocalPoolRecoveryNodeID: idWorker1,
				},
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef:         garagev1beta1.ClusterReference{Name: dsCluster},
				Zone:               testNodeZone,
				Capacity:           &capacity,
				Backing:            garagev1beta1.NodeBackingNodeLocalPool,
				KubernetesNodeName: dsWorker1,
				NodeLocalPoolName:  dsPool,
			},
		}
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, daemonSet, pod, node).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).Build()
		r := &GarageNodeReconciler{
			Client: fc,
			Scheme: scheme,
			nodeLocalPoolRecoveryNodeIDGetter: func(
				context.Context,
				*garagev1beta1.GarageNode,
				*garagev1beta2.GarageCluster,
				[]string,
			) (string, error) {
				return idWorker1, nil
			},
		}

		err := r.reconcileNode(bctx, node, cluster, gcl, cluster)
		Expect(stderrors.Is(err, errLayoutMutationPending)).To(BeTrue())
		Expect(node.Status.NodeID).To(Equal(idWorker1))
		Expect(fakeLayout.appliedChanges()).To(BeEmpty(), "recovery must not create a new layout role")
		Expect(r.reconcileNode(bctx, node, cluster, gcl, cluster)).To(Succeed())
		Expect(fakeLayout.appliedChanges()).To(BeEmpty())
	})

	It("rejects a retained HostPath whose live process identity changed", func() {
		capacity := resource.MustParse("100Gi")
		cluster, daemonSet := mkClusterAndDaemonSet()
		pod := mkDSPod("ds-disc-cluster-storage-mismatch", dsWorker1, "")
		pod.Annotations = nil
		pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: testStoragePodIP}
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ds-node-recovery-mismatch",
				Namespace: ns,
				Annotations: map[string]string{
					garagev1beta1.AnnotationNodeLocalPoolRecoveryNodeID: idWorker1,
				},
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef:         garagev1beta1.ClusterReference{Name: dsCluster},
				Zone:               testNodeZone,
				Capacity:           &capacity,
				Backing:            garagev1beta1.NodeBackingNodeLocalPool,
				KubernetesNodeName: dsWorker1,
				NodeLocalPoolName:  dsPool,
			},
		}
		fakeLayout := newFakeGarageLayout()
		srv := fakeLayout.server()
		defer srv.Close()
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, daemonSet, pod, node).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).Build()
		r := &GarageNodeReconciler{
			Client: fc,
			Scheme: scheme,
			nodeLocalPoolRecoveryNodeIDGetter: func(
				context.Context,
				*garagev1beta1.GarageNode,
				*garagev1beta2.GarageCluster,
				[]string,
			) (string, error) {
				return idWorker2, nil
			},
		}

		err := r.reconcileNode(bctx, node, cluster, garage.NewClient(srv.URL, "test-token"), cluster)
		Expect(stderrors.Is(err, errLayoutMutationPending)).To(BeTrue())
		Expect(err.Error()).To(ContainSubstring("live HostPath process reports"))
		Expect(node.Status.NodeID).To(BeEmpty())
		Expect(fakeLayout.appliedChanges()).To(BeEmpty())
	})

	It("rejects a matching process when its exact committed pool role is absent", func() {
		capacity := resource.MustParse("100Gi")
		cluster, daemonSet := mkClusterAndDaemonSet()
		pod := mkDSPod("ds-disc-cluster-storage-absent-role", dsWorker1, "")
		pod.Annotations = nil
		pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: testStoragePodIP}
		node := &garagev1beta1.GarageNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ds-node-recovery-absent-role",
				Namespace: ns,
				Annotations: map[string]string{
					garagev1beta1.AnnotationNodeLocalPoolRecoveryNodeID: idWorker1,
				},
			},
			Spec: garagev1beta1.GarageNodeSpec{
				ClusterRef:         garagev1beta1.ClusterReference{Name: dsCluster},
				Zone:               testNodeZone,
				Capacity:           &capacity,
				Backing:            garagev1beta1.NodeBackingNodeLocalPool,
				KubernetesNodeName: dsWorker1,
				NodeLocalPoolName:  dsPool,
			},
		}
		fakeLayout := newFakeGarageLayout()
		fakeLayout.statusNodes = []garage.NodeInfo{{
			ID: idWorker1, Address: ptr.To("10.0.0.11:3901"), IsUp: true,
		}}
		srv := fakeLayout.server()
		defer srv.Close()
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, daemonSet, pod, node).
			WithStatusSubresource(&garagev1beta1.GarageNode{}).Build()
		r := &GarageNodeReconciler{
			Client: fc,
			Scheme: scheme,
			nodeLocalPoolRecoveryNodeIDGetter: func(
				context.Context,
				*garagev1beta1.GarageNode,
				*garagev1beta2.GarageCluster,
				[]string,
			) (string, error) {
				return idWorker1, nil
			},
		}

		err := r.reconcileNode(bctx, node, cluster, garage.NewClient(srv.URL, "test-token"), cluster)
		Expect(stderrors.Is(err, errLayoutMutationPending)).To(BeTrue())
		Expect(err.Error()).To(ContainSubstring("no committed layout role"))
		Expect(node.Status.NodeID).To(BeEmpty())
		Expect(fakeLayout.appliedChanges()).To(BeEmpty())
	})
})
