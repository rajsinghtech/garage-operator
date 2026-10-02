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
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

const (
	vacNS        = "default"
	vacNodeName  = "vac-node"
	vacNodeUID   = types.UID("vac-node-uid")
	vacClusterNm = "vac-cluster"
	vacGold      = "gold"
	vacSilver    = "silver"
)

func vacTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	return managedPVCTestScheme(t)
}

func vacNode(metadataClass, dataClass *string) *garagev1beta1.GarageNode {
	meta := resource.MustParse("1Gi")
	data := resource.MustParse("10Gi")
	return &garagev1beta1.GarageNode{
		ObjectMeta: metav1.ObjectMeta{Name: vacNodeName, Namespace: vacNS, UID: vacNodeUID},
		Spec: garagev1beta1.GarageNodeSpec{
			ClusterRef: garagev1beta1.ClusterReference{Name: vacClusterNm},
			Storage: &garagev1beta1.NodeStorageConfig{
				Metadata: &garagev1beta1.NodeVolumeConfig{Size: &meta, VolumeAttributesClassName: metadataClass},
				Data:     &garagev1beta1.NodeVolumeConfig{Size: &data, VolumeAttributesClassName: dataClass},
			},
		},
	}
}

func vacPVC(template string, class *string, bound bool) *corev1.PersistentVolumeClaim {
	name := fmt.Sprintf("%s-%s-0", template, vacNodeName)
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: vacNS, UID: types.UID(name + "-uid"),
			Labels: map[string]string{
				labelAppManagedBy: operatorName, labelAppComponent: "node",
				labelGarageNode: vacNodeName, labelCluster: vacClusterNm,
			},
			Annotations: map[string]string{managedPVCNodeUIDAnnotation: string(vacNodeUID)},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:               []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources:                 corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")}},
			VolumeAttributesClassName: class,
		},
	}
	if bound {
		pvc.Status.Phase = corev1.ClaimBound
	} else {
		pvc.Status.Phase = corev1.ClaimPending
	}
	return pvc
}

func recordManaged(node *garagev1beta1.GarageNode, pvcs ...*corev1.PersistentVolumeClaim) {
	for _, pvc := range pvcs {
		node.Status.ManagedPVCs = append(node.Status.ManagedPVCs, garagev1beta1.ManagedNodePVCStatus{Name: pvc.Name, UID: pvc.UID})
	}
}

func vacNodeReconciler(t *testing.T, funcs interceptor.Funcs, node *garagev1beta1.GarageNode, pvcs ...*corev1.PersistentVolumeClaim) (*GarageNodeReconciler, client.Client) {
	t.Helper()
	scheme := vacTestScheme(t)
	recordManaged(node, pvcs...)
	builder := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta1.GarageNode{}, &garagev1beta2.GarageCluster{}, &corev1.PersistentVolumeClaim{}).
		WithInterceptorFuncs(funcs).WithObjects(node)
	for _, pvc := range pvcs {
		builder = builder.WithObjects(pvc)
	}
	fc := builder.Build()
	return &GarageNodeReconciler{Client: fc, Scheme: scheme}, fc
}

func vacCluster() *garagev1beta2.GarageCluster {
	return &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{Name: vacClusterNm, Namespace: vacNS, UID: "vac-cluster-uid"}}
}

func getPVC(t *testing.T, c client.Client, name string) *corev1.PersistentVolumeClaim {
	t.Helper()
	pvc := &corev1.PersistentVolumeClaim{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: name, Namespace: vacNS}, pvc); err != nil {
		t.Fatal(err)
	}
	return pvc
}

func vacCondition(t *testing.T, c client.Client) *metav1.Condition {
	t.Helper()
	node := &garagev1beta1.GarageNode{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: vacNodeName, Namespace: vacNS}, node); err != nil {
		t.Fatal(err)
	}
	return meta.FindStatusCondition(node.Status.Conditions, garagev1beta1.ConditionVolumeAttributesClassApplied)
}

func requireVACCondition(t *testing.T, c client.Client, status metav1.ConditionStatus, reason string) *metav1.Condition {
	t.Helper()
	cond := vacCondition(t, c)
	if cond == nil {
		t.Fatalf("condition %s missing", garagev1beta1.ConditionVolumeAttributesClassApplied)
	}
	if cond.Status != status || cond.Reason != reason {
		t.Fatalf("condition = %s/%s (%s), want %s/%s", cond.Status, cond.Reason, cond.Message, status, reason)
	}
	return cond
}

func TestNodeVolumeAttributesClaimsListsOnlyOperatorGeneratedClaims(t *testing.T) {
	node := vacNode(ptr.To(vacGold), ptr.To(vacSilver))
	got := nodeVolumeAttributesClaims(node)
	if len(got) != 2 || got[0] != (vacDesiredClaim{claim: "metadata-vac-node-0", class: vacGold}) ||
		got[1] != (vacDesiredClaim{claim: "data-vac-node-0", class: vacSilver}) {
		t.Fatalf("claims = %#v", got)
	}

	node.Spec.Storage.Metadata.ExistingClaim = "adopted"
	node.Spec.Storage.Data.Type = garagev1beta1.VolumeTypeEmptyDir
	if got := nodeVolumeAttributesClaims(node); len(got) != 0 {
		t.Fatalf("existingClaim and EmptyDir volumes are never operator-generated claims: %#v", got)
	}

	node = vacNode(ptr.To(vacGold), ptr.To(vacSilver))
	node.Spec.Gateway = true
	if got := nodeVolumeAttributesClaims(node); len(got) != 1 || got[0].claim != "metadata-vac-node-0" {
		t.Fatalf("gateway nodes only carry a metadata claim: %#v", got)
	}

	node = vacNode(nil, ptr.To(""))
	if got := nodeVolumeAttributesClaims(node); len(got) != 0 {
		t.Fatalf("unset and empty classes request nothing: %#v", got)
	}

	node = vacNode(nil, nil)
	node.Spec.Storage.Data = nil
	node.Spec.Storage.DataPaths = []garagev1beta1.NodeVolumeConfig{
		{Size: ptr.To(resource.MustParse("5Gi")), VolumeAttributesClassName: ptr.To(vacGold)},
		{Size: ptr.To(resource.MustParse("5Gi"))},
		{Size: ptr.To(resource.MustParse("5Gi")), VolumeAttributesClassName: ptr.To(vacSilver)},
	}
	got = nodeVolumeAttributesClaims(node)
	if len(got) != 2 || got[0].claim != fmt.Sprintf("%s-%s-0", nodeMultiHDDDataVolName(0), vacNodeName) || got[0].class != vacGold ||
		got[1].claim != fmt.Sprintf("%s-%s-0", nodeMultiHDDDataVolName(2), vacNodeName) || got[1].class != vacSilver {
		t.Fatalf("multi-HDD claims = %#v", got)
	}
}

func TestEvaluateClaimVolumeAttributes(t *testing.T) {
	bound := func(mutate func(*corev1.PersistentVolumeClaim)) *corev1.PersistentVolumeClaim {
		pvc := vacPVC("data", nil, true)
		mutate(pvc)
		return pvc
	}
	cases := []struct {
		name      string
		pvc       *corev1.PersistentVolumeClaim
		wantPatch bool
		wantReas  string
	}{
		{"pending claim", vacPVC("data", nil, false), false, garagev1beta1.ReasonVolumeAttributesClassWaitingForBind},
		{"bound without class", vacPVC("data", nil, true), true, garagev1beta1.ReasonVolumeAttributesClassModifyInProgress},
		{"bound with other class", vacPVC("data", ptr.To(vacSilver), true), true, garagev1beta1.ReasonVolumeAttributesClassModifyInProgress},
		{"requested but driver not caught up", vacPVC("data", ptr.To(vacGold), true), false, garagev1beta1.ReasonVolumeAttributesClassModifyInProgress},
		{"applied", bound(func(p *corev1.PersistentVolumeClaim) {
			p.Spec.VolumeAttributesClassName = ptr.To(vacGold)
			p.Status.CurrentVolumeAttributesClassName = ptr.To(vacGold)
		}), false, garagev1beta1.ReasonVolumeAttributesClassApplied},
		{"modify pending", bound(func(p *corev1.PersistentVolumeClaim) {
			p.Spec.VolumeAttributesClassName = ptr.To(vacGold)
			p.Status.CurrentVolumeAttributesClassName = ptr.To(vacSilver)
			p.Status.ModifyVolumeStatus = &corev1.ModifyVolumeStatus{TargetVolumeAttributesClassName: vacGold, Status: corev1.PersistentVolumeClaimModifyVolumePending}
		}), false, garagev1beta1.ReasonVolumeAttributesClassModifyInProgress},
		{"modify in progress", bound(func(p *corev1.PersistentVolumeClaim) {
			p.Spec.VolumeAttributesClassName = ptr.To(vacGold)
			p.Status.ModifyVolumeStatus = &corev1.ModifyVolumeStatus{TargetVolumeAttributesClassName: vacGold, Status: corev1.PersistentVolumeClaimModifyVolumeInProgress}
		}), false, garagev1beta1.ReasonVolumeAttributesClassModifyInProgress},
		{"infeasible", bound(func(p *corev1.PersistentVolumeClaim) {
			p.Spec.VolumeAttributesClassName = ptr.To(vacGold)
			p.Status.CurrentVolumeAttributesClassName = ptr.To(vacSilver)
			p.Status.ModifyVolumeStatus = &corev1.ModifyVolumeStatus{TargetVolumeAttributesClassName: vacGold, Status: corev1.PersistentVolumeClaimModifyVolumeInfeasible}
		}), false, garagev1beta1.ReasonVolumeAttributesClassInfeasible},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			needsPatch, reason, message := evaluateClaimVolumeAttributes(tc.pvc, vacGold)
			if needsPatch != tc.wantPatch || reason != tc.wantReas || message == "" {
				t.Fatalf("got patch=%v reason=%s message=%q, want patch=%v reason=%s", needsPatch, reason, message, tc.wantPatch, tc.wantReas)
			}
		})
	}
}

func TestAggregateVolumeAttributesStates(t *testing.T) {
	if got := aggregateVolumeAttributesStates(nil); got != nil {
		t.Fatalf("no claims must produce no condition, got %#v", got)
	}
	applied := vacClaimState{claim: "a", reason: garagev1beta1.ReasonVolumeAttributesClassApplied, message: "ok"}
	cond := aggregateVolumeAttributesStates([]vacClaimState{applied, applied})
	if cond.Status != metav1.ConditionTrue || cond.Reason != garagev1beta1.ReasonVolumeAttributesClassApplied {
		t.Fatalf("all applied = %#v", cond)
	}
	cond = aggregateVolumeAttributesStates([]vacClaimState{
		applied,
		{claim: "b", reason: garagev1beta1.ReasonVolumeAttributesClassModifyInProgress, message: "b is modifying"},
		{claim: "c", reason: garagev1beta1.ReasonVolumeAttributesClassInfeasible, message: "c infeasible"},
		{claim: "d", reason: garagev1beta1.ReasonVolumeAttributesClassWaitingForBind, message: "d pending"},
	})
	if cond.Status != metav1.ConditionFalse || cond.Reason != garagev1beta1.ReasonVolumeAttributesClassInfeasible {
		t.Fatalf("most severe reason must win: %#v", cond)
	}
	if strings.Contains(cond.Message, "ok") || !strings.Contains(cond.Message, "c infeasible") ||
		!strings.Contains(cond.Message, "b is modifying") || !strings.Contains(cond.Message, "d pending") {
		t.Fatalf("message must list only unfinished claims: %q", cond.Message)
	}
	cond = aggregateVolumeAttributesStates([]vacClaimState{
		{claim: "x", reason: garagev1beta1.ReasonVolumeAttributesClassInfeasible},
		{claim: "y", reason: garagev1beta1.ReasonVolumeAttributesClassUnsupported},
	})
	if cond.Reason != garagev1beta1.ReasonVolumeAttributesClassUnsupported {
		t.Fatalf("Unsupported outranks Infeasible: %#v", cond)
	}
}

func TestReconcileNodePVCAttributesPatchesBoundClaims(t *testing.T) {
	ctx := context.Background()
	node := vacNode(ptr.To(vacGold), ptr.To(vacSilver))
	metaPVC := vacPVC("metadata", nil, true)
	dataPVC := vacPVC("data", ptr.To("operator-stale"), true)
	r, fc := vacNodeReconciler(t, interceptor.Funcs{}, node, metaPVC, dataPVC)

	if err := r.reconcileNodePVCAttributes(ctx, node, vacCluster()); err != nil {
		t.Fatal(err)
	}
	if got := getPVC(t, fc, metaPVC.Name).Spec.VolumeAttributesClassName; got == nil || *got != vacGold {
		t.Fatalf("metadata class = %v, want %s", got, vacGold)
	}
	if got := getPVC(t, fc, dataPVC.Name).Spec.VolumeAttributesClassName; got == nil || *got != vacSilver {
		t.Fatalf("a drifted class must be overwritten by the spec, got %v", got)
	}
	// Nothing but the class changed: size and labels are untouched.
	if got := getPVC(t, fc, metaPVC.Name); got.Spec.Resources.Requests[corev1.ResourceStorage] != resource.MustParse("1Gi") ||
		got.Labels[labelGarageNode] != vacNodeName {
		t.Fatalf("patch rewrote unrelated PVC fields: %#v", got.Spec)
	}
	requireVACCondition(t, fc, metav1.ConditionFalse, garagev1beta1.ReasonVolumeAttributesClassModifyInProgress)
}

func TestReconcileNodePVCAttributesSkipsPendingClaims(t *testing.T) {
	ctx := context.Background()
	node := vacNode(ptr.To(vacGold), nil)
	pending := vacPVC("metadata", nil, false)
	var patches int
	r, fc := vacNodeReconciler(t, interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
		if _, ok := obj.(*corev1.PersistentVolumeClaim); ok {
			patches++
		}
		return c.Patch(ctx, obj, p, opts...)
	}}, node, pending)

	if err := r.reconcileNodePVCAttributes(ctx, node, vacCluster()); err != nil {
		t.Fatal(err)
	}
	if patches != 0 {
		t.Fatalf("a Pending claim must not be patched (Kubernetes forbids it), got %d patches", patches)
	}
	requireVACCondition(t, fc, metav1.ConditionFalse, garagev1beta1.ReasonVolumeAttributesClassWaitingForBind)
}

func TestReconcileNodePVCAttributesLeavesClaimsAloneWhenSpecUnset(t *testing.T) {
	ctx := context.Background()
	node := vacNode(nil, nil)
	pvc := vacPVC("metadata", ptr.To("admin-chosen"), true)
	var patches int
	r, fc := vacNodeReconciler(t, interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
		if _, ok := obj.(*corev1.PersistentVolumeClaim); ok {
			patches++
		}
		return c.Patch(ctx, obj, p, opts...)
	}}, node, pvc)
	node.Status.Conditions = []metav1.Condition{{
		Type: garagev1beta1.ConditionVolumeAttributesClassApplied, Status: metav1.ConditionTrue,
		Reason: garagev1beta1.ReasonVolumeAttributesClassApplied, LastTransitionTime: metav1.Now(),
	}}
	if err := fc.Status().Update(ctx, node); err != nil {
		t.Fatal(err)
	}

	if err := r.reconcileNodePVCAttributes(ctx, node, vacCluster()); err != nil {
		t.Fatal(err)
	}
	if patches != 0 {
		t.Fatalf("an unset spec means hands off, got %d patches", patches)
	}
	if got := getPVC(t, fc, pvc.Name).Spec.VolumeAttributesClassName; got == nil || *got != "admin-chosen" {
		t.Fatalf("admin-chosen class was modified: %v", got)
	}
	if vacCondition(t, fc) != nil {
		t.Fatal("the condition must be removed when no class is desired")
	}
}

func TestReconcileNodePVCAttributesReportsApplied(t *testing.T) {
	ctx := context.Background()
	node := vacNode(ptr.To(vacGold), nil)
	pvc := vacPVC("metadata", ptr.To(vacGold), true)
	pvc.Status.CurrentVolumeAttributesClassName = ptr.To(vacGold)
	r, fc := vacNodeReconciler(t, interceptor.Funcs{}, node, pvc)
	if err := r.reconcileNodePVCAttributes(ctx, node, vacCluster()); err != nil {
		t.Fatal(err)
	}
	requireVACCondition(t, fc, metav1.ConditionTrue, garagev1beta1.ReasonVolumeAttributesClassApplied)
}

func TestReconcileNodePVCAttributesReportsInfeasible(t *testing.T) {
	ctx := context.Background()
	node := vacNode(ptr.To(vacGold), nil)
	pvc := vacPVC("metadata", ptr.To(vacGold), true)
	pvc.Status.CurrentVolumeAttributesClassName = ptr.To(vacSilver)
	pvc.Status.ModifyVolumeStatus = &corev1.ModifyVolumeStatus{
		TargetVolumeAttributesClassName: vacGold, Status: corev1.PersistentVolumeClaimModifyVolumeInfeasible,
	}
	r, fc := vacNodeReconciler(t, interceptor.Funcs{}, node, pvc)
	if err := r.reconcileNodePVCAttributes(ctx, node, vacCluster()); err != nil {
		t.Fatal(err)
	}
	cond := requireVACCondition(t, fc, metav1.ConditionFalse, garagev1beta1.ReasonVolumeAttributesClassInfeasible)
	if !strings.Contains(cond.Message, vacGold) {
		t.Fatalf("message should name the rejected class: %q", cond.Message)
	}
}

func TestReconcileNodePVCAttributesMissingClaimWaits(t *testing.T) {
	ctx := context.Background()
	node := vacNode(ptr.To(vacGold), nil)
	r, fc := vacNodeReconciler(t, interceptor.Funcs{}, node)
	if err := r.reconcileNodePVCAttributes(ctx, node, vacCluster()); err != nil {
		t.Fatal(err)
	}
	requireVACCondition(t, fc, metav1.ConditionFalse, garagev1beta1.ReasonVolumeAttributesClassWaitingForBind)
}

func TestReconcileNodePVCAttributesUnsupportedAPIServerBacksOff(t *testing.T) {
	ctx := context.Background()
	node := vacNode(ptr.To(vacGold), nil)
	pvc := vacPVC("metadata", nil, true)
	var patches int
	r, fc := vacNodeReconciler(t, interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
		if _, ok := obj.(*corev1.PersistentVolumeClaim); ok {
			patches++
			return apierrors.NewForbidden(schema.GroupResource{Resource: "persistentvolumeclaims"}, obj.GetName(),
				fmt.Errorf("update is forbidden when the VolumeAttributesClass feature gate is disabled"))
		}
		return c.Patch(ctx, obj, p, opts...)
	}}, node, pvc)

	for i := 0; i < 3; i++ {
		if err := r.reconcileNodePVCAttributes(ctx, node, vacCluster()); err != nil {
			t.Fatalf("an unsupported feature must be reported on the condition, not failed: %v", err)
		}
	}
	if patches != 1 {
		t.Fatalf("unsupported clusters must be probed once per backoff window, got %d patches", patches)
	}
	cond := requireVACCondition(t, fc, metav1.ConditionFalse, garagev1beta1.ReasonVolumeAttributesClassUnsupported)
	if !strings.Contains(cond.Message, "1.34") {
		t.Fatalf("message should state the version requirement: %q", cond.Message)
	}
}

func TestReconcileNodePVCAttributesDroppedFieldIsUnsupported(t *testing.T) {
	ctx := context.Background()
	node := vacNode(ptr.To(vacGold), nil)
	pvc := vacPVC("metadata", nil, true)
	// A server with the feature gate off silently drops the field: the patch
	// succeeds but the returned claim has no class.
	r, fc := vacNodeReconciler(t, interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
		if claim, ok := obj.(*corev1.PersistentVolumeClaim); ok {
			claim.Spec.VolumeAttributesClassName = nil
			return nil
		}
		return c.Patch(ctx, obj, p, opts...)
	}}, node, pvc)
	if err := r.reconcileNodePVCAttributes(ctx, node, vacCluster()); err != nil {
		t.Fatal(err)
	}
	requireVACCondition(t, fc, metav1.ConditionFalse, garagev1beta1.ReasonVolumeAttributesClassUnsupported)
}

func TestReconcileNodePVCAttributesRefusesUnprovenClaims(t *testing.T) {
	ctx := context.Background()
	node := vacNode(ptr.To(vacGold), nil)
	pvc := vacPVC("metadata", nil, true)
	var patches int
	r, fc := vacNodeReconciler(t, interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
		if _, ok := obj.(*corev1.PersistentVolumeClaim); ok {
			patches++
		}
		return c.Patch(ctx, obj, p, opts...)
	}}, node, pvc)
	// Same name, different UID than the reservation recorded on the node: a
	// recreated or foreign claim.
	node.Status.ManagedPVCs[0].UID = "someone-elses-uid"
	if err := fc.Status().Update(ctx, node); err != nil {
		t.Fatal(err)
	}
	err := r.reconcileNodePVCAttributes(ctx, node, vacCluster())
	if err == nil || !strings.Contains(err.Error(), "refusing managed PVC") {
		t.Fatalf("want provenance refusal, got %v", err)
	}
	if patches != 0 {
		t.Fatalf("an unproven claim must never be patched, got %d patches", patches)
	}
}

func TestReconcileNodePVCAttributesRetryableFailureIsInProgress(t *testing.T) {
	ctx := context.Background()
	node := vacNode(ptr.To(vacGold), nil)
	pvc := vacPVC("metadata", nil, true)
	r, fc := vacNodeReconciler(t, interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
		if _, ok := obj.(*corev1.PersistentVolumeClaim); ok {
			return apierrors.NewServiceUnavailable("etcd is busy")
		}
		return c.Patch(ctx, obj, p, opts...)
	}}, node, pvc)
	if err := r.reconcileNodePVCAttributes(ctx, node, vacCluster()); err != nil {
		t.Fatalf("a transient patch failure is reported, not fatal: %v", err)
	}
	requireVACCondition(t, fc, metav1.ConditionFalse, garagev1beta1.ReasonVolumeAttributesClassModifyInProgress)
}

func TestVACUnsupportedBackoff(t *testing.T) {
	var b vacUnsupportedBackoff
	now := time.Now()
	if b.active("uid", now) {
		t.Fatal("fresh backoff must be inactive")
	}
	b.arm("uid", now)
	if !b.active("uid", now.Add(time.Second)) || b.active("uid", now.Add(RequeueAfterLong+time.Second)) {
		t.Fatal("backoff should last exactly RequeueAfterLong")
	}
	b.clear("uid")
	if b.active("uid", now) {
		t.Fatal("cleared backoff must be inactive")
	}
	b.arm("", now)
	if b.active("", now) {
		t.Fatal("an empty UID is never remembered")
	}
}

func TestIsVolumeAttributesClassUnsupported(t *testing.T) {
	gr := schema.GroupResource{Resource: "persistentvolumeclaims"}
	if !isVolumeAttributesClassUnsupported(apierrors.NewForbidden(gr, "x", fmt.Errorf("no"))) ||
		!isVolumeAttributesClassUnsupported(apierrors.NewInvalid(schema.GroupKind{Kind: "PersistentVolumeClaim"}, "x", nil)) {
		t.Fatal("Forbidden and Invalid mean unsupported")
	}
	if isVolumeAttributesClassUnsupported(apierrors.NewConflict(gr, "x", fmt.Errorf("c"))) ||
		isVolumeAttributesClassUnsupported(apierrors.NewServiceUnavailable("x")) {
		t.Fatal("conflicts and outages are retryable, not unsupported")
	}
}

func TestPVCVolumeAttributesPredicate(t *testing.T) {
	p := pvcVolumeAttributesPredicate()
	base := vacPVC("data", nil, true)
	mutated := func(f func(*corev1.PersistentVolumeClaim)) *corev1.PersistentVolumeClaim {
		c := base.DeepCopy()
		f(c)
		return c
	}
	update := func(n *corev1.PersistentVolumeClaim) bool {
		return p.Update(event.UpdateEvent{ObjectOld: base, ObjectNew: n})
	}
	for name, n := range map[string]*corev1.PersistentVolumeClaim{
		"requested class": mutated(func(c *corev1.PersistentVolumeClaim) { c.Spec.VolumeAttributesClassName = ptr.To(vacGold) }),
		"current class":   mutated(func(c *corev1.PersistentVolumeClaim) { c.Status.CurrentVolumeAttributesClassName = ptr.To(vacGold) }),
		"modify status": mutated(func(c *corev1.PersistentVolumeClaim) {
			c.Status.ModifyVolumeStatus = &corev1.ModifyVolumeStatus{Status: corev1.PersistentVolumeClaimModifyVolumeInfeasible}
		}),
		"phase transition": mutated(func(c *corev1.PersistentVolumeClaim) { c.Status.Phase = corev1.ClaimLost }),
	} {
		if !update(n) {
			t.Errorf("%s must wake the GarageNode controller", name)
		}
	}
	for name, n := range map[string]*corev1.PersistentVolumeClaim{
		"label":      mutated(func(c *corev1.PersistentVolumeClaim) { c.Labels["x"] = "y" }),
		"annotation": mutated(func(c *corev1.PersistentVolumeClaim) { c.Annotations["x"] = "y" }),
		"finalizer":  mutated(func(c *corev1.PersistentVolumeClaim) { c.Finalizers = []string{managedPVCFinalizer} }),
		"capacity": mutated(func(c *corev1.PersistentVolumeClaim) {
			c.Status.Capacity = corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("2Gi")}
		}),
		"unchanged copy": base.DeepCopy(),
	} {
		if update(n) {
			t.Errorf("%s must not wake the GarageNode controller", name)
		}
	}
	if p.Delete(event.DeleteEvent{Object: base}) || p.Generic(event.GenericEvent{Object: base}) {
		t.Error("delete/generic events are ignored")
	}
	if p.Create(event.CreateEvent{Object: base}) {
		t.Error("a new claim without any class state is ignored")
	}
	if !p.Create(event.CreateEvent{Object: mutated(func(c *corev1.PersistentVolumeClaim) { c.Spec.VolumeAttributesClassName = ptr.To(vacGold) })}) {
		t.Error("a new claim that requests a class must wake the controller")
	}
}

func TestNodeForManagedPVC(t *testing.T) {
	r := &GarageNodeReconciler{}
	if got := r.nodeForManagedPVC(context.Background(), vacPVC("data", nil, true)); len(got) != 1 ||
		got[0].Name != vacNodeName || got[0].Namespace != vacNS {
		t.Fatalf("mapped = %#v", got)
	}
	foreign := vacPVC("data", nil, true)
	foreign.Labels = map[string]string{"app": "other"}
	if got := r.nodeForManagedPVC(context.Background(), foreign); len(got) != 0 {
		t.Fatalf("foreign claims must not be mapped: %#v", got)
	}
	if got := r.nodeForManagedPVC(context.Background(), &corev1.Pod{}); len(got) != 0 {
		t.Fatalf("non-PVC objects must not be mapped: %#v", got)
	}
}

// --- StatefulSet claim templates, Auto-mode projection -----------------------

func TestClaimTemplatesCarryVolumeAttributesClass(t *testing.T) {
	r := &GarageNodeReconciler{}
	node := vacNode(ptr.To(vacGold), ptr.To(vacSilver))
	templates := r.buildNodeVolumeClaimTemplates(node, vacCluster())
	byName := map[string]corev1.PersistentVolumeClaim{}
	for _, tpl := range templates {
		byName[tpl.Name] = tpl
	}
	if got := byName[metadataVolName].Spec.VolumeAttributesClassName; got == nil || *got != vacGold {
		t.Fatalf("metadata template class = %v", got)
	}
	if got := byName[dataVolName].Spec.VolumeAttributesClassName; got == nil || *got != vacSilver {
		t.Fatalf("data template class = %v", got)
	}

	// Absent stays absent so existing templates serialise unchanged.
	node = vacNode(nil, ptr.To(""))
	for _, tpl := range r.buildNodeVolumeClaimTemplates(node, vacCluster()) {
		if tpl.Spec.VolumeAttributesClassName != nil {
			t.Fatalf("template %s must not carry a class: %v", tpl.Name, *tpl.Spec.VolumeAttributesClassName)
		}
	}

	node = vacNode(nil, nil)
	node.Spec.Storage.Data = nil
	node.Spec.Storage.DataPaths = []garagev1beta1.NodeVolumeConfig{
		{Size: ptr.To(resource.MustParse("5Gi")), VolumeAttributesClassName: ptr.To(vacGold)},
		{Size: ptr.To(resource.MustParse("5Gi"))},
	}
	templates = r.buildNodeVolumeClaimTemplates(node, vacCluster())
	for _, tpl := range templates {
		switch tpl.Name {
		case nodeMultiHDDDataVolName(0):
			if got := tpl.Spec.VolumeAttributesClassName; got == nil || *got != vacGold {
				t.Fatalf("path 0 template class = %v", got)
			}
		case nodeMultiHDDDataVolName(1):
			if tpl.Spec.VolumeAttributesClassName != nil {
				t.Fatalf("path 1 must not carry a class")
			}
		}
	}
}

func TestEdgeGatewayClaimTemplateCarriesVolumeAttributesClass(t *testing.T) {
	cluster := vacEdgeGatewayCluster(ptr.To(vacGold))
	templates := buildGatewayVolumeClaimTemplates(cluster)
	if len(templates) != 1 || templates[0].Spec.VolumeAttributesClassName == nil || *templates[0].Spec.VolumeAttributesClassName != vacGold {
		t.Fatalf("templates = %#v", templates)
	}
	cluster.Spec.Gateway.Metadata.VolumeAttributesClassName = nil
	if got := buildGatewayVolumeClaimTemplates(cluster)[0].Spec.VolumeAttributesClassName; got != nil {
		t.Fatalf("absent class must stay absent, got %v", *got)
	}
}

func TestGatewayClaimTemplateChangeDetectionIgnoresVolumeAttributesClass(t *testing.T) {
	// volumeClaimTemplates are immutable on a StatefulSet, so a class change must
	// never be reported as a template change (that would force a delete/recreate).
	existing := buildGatewayVolumeClaimTemplates(vacEdgeGatewayCluster(nil))
	desired := buildGatewayVolumeClaimTemplates(vacEdgeGatewayCluster(ptr.To(vacGold)))
	if gatewayVolumeClaimTemplatesChanged(existing, desired) {
		t.Fatal("a VolumeAttributesClass difference must not count as a claim template change")
	}
}

func vacAutoCluster() *garagev1beta2.GarageCluster {
	return &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: vacClusterNm, Namespace: vacNS, UID: "vac-cluster-uid"},
		Spec: garagev1beta2.GarageClusterSpec{
			LayoutPolicy: LayoutPolicyAuto,
			Storage: &garagev1beta2.StorageSpec{
				Replicas: 1,
				Metadata: &garagev1beta2.VolumeConfig{Size: ptr.To(resource.MustParse("1Gi")), VolumeAttributesClassName: ptr.To(vacGold)},
				Data:     &garagev1beta2.VolumeConfig{Size: ptr.To(resource.MustParse("10Gi")), VolumeAttributesClassName: ptr.To(vacSilver)},
			},
			Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
		},
	}
}

func TestAutoModeStorageNodeProjectsVolumeAttributesClass(t *testing.T) {
	r := &GarageClusterReconciler{Scheme: vacTestScheme(t)}
	cluster := vacAutoCluster()
	node, err := r.buildAutoModeStorageNode(cluster, 0, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := node.Spec.Storage.Metadata.VolumeAttributesClassName; got == nil || *got != vacGold {
		t.Fatalf("metadata class = %v", got)
	}
	if got := node.Spec.Storage.Data.VolumeAttributesClassName; got == nil || *got != vacSilver {
		t.Fatalf("data class = %v", got)
	}
	// The projection is a copy, not an alias of the cluster's pointer.
	*node.Spec.Storage.Data.VolumeAttributesClassName = "mutated"
	if *cluster.Spec.Storage.Data.VolumeAttributesClassName != vacSilver {
		t.Fatal("child class aliases the cluster spec")
	}

	// A live class change is propagated to an existing child and detected as drift.
	current := node.DeepCopy()
	changed := vacAutoCluster()
	changed.Spec.Storage.Metadata.VolumeAttributesClassName = ptr.To("platinum")
	changed.Spec.Storage.Data.VolumeAttributesClassName = nil
	desired, err := r.buildAutoModeStorageNode(changed, 0, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	current.Spec.Storage.Data.VolumeAttributesClassName = ptr.To(vacSilver)
	if !autoModeStorageNodeNeedsUpdate(current, desired) {
		t.Fatal("class drift must trigger a child update")
	}
	applyAutoModeStorageNodeUpdate(current, desired)
	if got := current.Spec.Storage.Metadata.VolumeAttributesClassName; got == nil || *got != "platinum" {
		t.Fatalf("metadata class after update = %v", got)
	}
	if current.Spec.Storage.Data.VolumeAttributesClassName != nil {
		t.Fatalf("removing the class at the cluster must clear it on the child, got %v", *current.Spec.Storage.Data.VolumeAttributesClassName)
	}
	if autoModeStorageNodeNeedsUpdate(current, desired) {
		t.Fatal("no drift expected after applying the update")
	}
}

func TestAutoModeStorageNodePathsDoNotInheritTopLevelClass(t *testing.T) {
	r := &GarageClusterReconciler{Scheme: vacTestScheme(t)}
	cluster := vacAutoCluster()
	cluster.Spec.Storage.Data = &garagev1beta2.VolumeConfig{
		VolumeAttributesClassName: ptr.To(vacSilver),
		Paths: []garagev1beta2.DataPath{
			{Path: "/data/a", Capacity: ptr.To(resource.MustParse("5Gi")), Volume: &garagev1beta2.DataPathVolumeConfig{Size: ptr.To(resource.MustParse("5Gi")), VolumeAttributesClassName: ptr.To(vacGold)}},
			{Path: "/data/b", Capacity: ptr.To(resource.MustParse("5Gi")), Volume: &garagev1beta2.DataPathVolumeConfig{Size: ptr.To(resource.MustParse("5Gi"))}},
		},
	}
	node, err := r.buildAutoModeStorageNode(cluster, 0, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	paths := node.Spec.Storage.DataPaths
	if len(paths) != 2 {
		t.Fatalf("dataPaths = %#v", paths)
	}
	if got := paths[0].VolumeAttributesClassName; got == nil || *got != vacGold {
		t.Fatalf("path a class = %v", got)
	}
	if paths[1].VolumeAttributesClassName != nil {
		t.Fatalf("path b must not inherit the top-level class, got %q", *paths[1].VolumeAttributesClassName)
	}

	changed := cluster.DeepCopy()
	changed.Spec.Storage.Data.Paths[1].Volume.VolumeAttributesClassName = ptr.To("platinum")
	desired, err := r.buildAutoModeStorageNode(changed, 0, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !autoModeStorageNodeNeedsUpdate(node, desired) {
		t.Fatal("a per-path class change must be detected as drift")
	}
}

func vacEdgeGatewayCluster(class *string) *garagev1beta2.GarageCluster {
	return &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: vacClusterNm, Namespace: vacNS, UID: "vac-cluster-uid"},
		Spec: garagev1beta2.GarageClusterSpec{
			Gateway: &garagev1beta2.GatewaySpec{
				Replicas: 2,
				Metadata: &garagev1beta2.VolumeConfig{Size: ptr.To(resource.MustParse("1Gi")), VolumeAttributesClassName: class},
			},
			Replication: &garagev1beta2.ReplicationConfig{Factor: 1},
		},
	}
}

func TestUnifiedGatewayNodeProjectsVolumeAttributesClass(t *testing.T) {
	r := &GarageClusterReconciler{Scheme: vacTestScheme(t)}
	cluster := vacAutoCluster()
	cluster.Spec.Gateway = &garagev1beta2.GatewaySpec{
		Replicas: 1,
		Metadata: &garagev1beta2.VolumeConfig{Size: ptr.To(resource.MustParse("1Gi")), VolumeAttributesClassName: ptr.To(vacGold)},
	}
	node, err := r.buildAutoModeGatewayNode(cluster, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := node.Spec.Storage.Metadata.VolumeAttributesClassName; got == nil || *got != vacGold {
		t.Fatalf("gateway child class = %v", got)
	}
	templates := (&GarageNodeReconciler{}).buildNodeVolumeClaimTemplates(node, cluster)
	if len(templates) != 1 || templates[0].Spec.VolumeAttributesClassName == nil || *templates[0].Spec.VolumeAttributesClassName != vacGold {
		t.Fatalf("gateway child template = %#v", templates)
	}

	current := node.DeepCopy()
	cluster.Spec.Gateway.Metadata.VolumeAttributesClassName = ptr.To(vacSilver)
	desired, err := r.buildAutoModeGatewayNode(cluster, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if !autoModeGatewayNodeNeedsUpdate(current, desired) {
		t.Fatal("gateway class drift must trigger a child update")
	}
	applyAutoModeGatewayNodeUpdate(current, desired)
	if got := current.Spec.Storage.Metadata.VolumeAttributesClassName; got == nil || *got != vacSilver {
		t.Fatalf("gateway child class after update = %v", got)
	}
}

// --- edge gateway claims and the cluster aggregate ---------------------------

func vacEdgeGatewayReconciler(t *testing.T, funcs interceptor.Funcs, cluster *garagev1beta2.GarageCluster, withSTS bool, objs ...client.Object) (*GarageClusterReconciler, client.Client) {
	t.Helper()
	scheme := vacTestScheme(t)
	builder := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta2.GarageCluster{}, &garagev1beta1.GarageNode{}).
		WithInterceptorFuncs(funcs).WithObjects(cluster).WithObjects(objs...)
	if withSTS {
		sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: gatewayWorkloadName(cluster), Namespace: vacNS, UID: "gw-sts-uid"}}
		if err := controllerutil.SetControllerReference(cluster, sts, scheme); err != nil {
			t.Fatal(err)
		}
		builder = builder.WithObjects(sts)
	}
	fc := builder.Build()
	return &GarageClusterReconciler{Client: fc, Scheme: scheme}, fc
}

func vacGatewayPVC(cluster *garagev1beta2.GarageCluster, ordinal int32, bound bool) *corev1.PersistentVolumeClaim {
	r := &GarageClusterReconciler{}
	name := gatewayVolumeAttributesClaim(cluster, ordinal)
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: vacNS, UID: types.UID(name + "-uid"), Labels: r.selectorLabelsForTier(cluster, tierGateway)},
		Spec:       corev1.PersistentVolumeClaimSpec{},
	}
	if bound {
		pvc.Status.Phase = corev1.ClaimBound
	}
	return pvc
}

func TestEdgeGatewayVolumeAttributesClass(t *testing.T) {
	cluster := vacEdgeGatewayCluster(ptr.To(vacGold))
	if got := edgeGatewayVolumeAttributesClass(cluster); got != vacGold {
		t.Fatalf("class = %q", got)
	}
	cluster.Spec.Gateway.Metadata.Type = garagev1beta2.VolumeTypeEmptyDir
	if got := edgeGatewayVolumeAttributesClass(cluster); got != "" {
		t.Fatalf("EmptyDir has no claim, got %q", got)
	}
	unified := vacAutoCluster()
	unified.Spec.Gateway = &garagev1beta2.GatewaySpec{Replicas: 1, Metadata: &garagev1beta2.VolumeConfig{VolumeAttributesClassName: ptr.To(vacGold)}}
	if got := edgeGatewayVolumeAttributesClass(unified); got != "" {
		t.Fatalf("unified gateway claims belong to GarageNodes, got %q", got)
	}
	manual := vacEdgeGatewayCluster(ptr.To(vacGold))
	manual.Spec.LayoutPolicy = LayoutPolicyManual
	if got := edgeGatewayVolumeAttributesClass(manual); got != "" {
		t.Fatalf("manual layout gateways are not operator-owned, got %q", got)
	}
}

func TestReconcileGatewayPVCAttributes(t *testing.T) {
	ctx := context.Background()
	cluster := vacEdgeGatewayCluster(ptr.To(vacGold))
	bound := vacGatewayPVC(cluster, 0, true)
	pending := vacGatewayPVC(cluster, 1, false)
	r, fc := vacEdgeGatewayReconciler(t, interceptor.Funcs{}, cluster, true, bound, pending)

	states, err := r.reconcileGatewayPVCAttributes(ctx, cluster)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 {
		t.Fatalf("states = %#v", states)
	}
	if got := getPVC(t, fc, bound.Name).Spec.VolumeAttributesClassName; got == nil || *got != vacGold {
		t.Fatalf("bound gateway claim class = %v", got)
	}
	if getPVC(t, fc, pending.Name).Spec.VolumeAttributesClassName != nil {
		t.Fatal("a Pending gateway claim must not be patched")
	}
	if states[0].reason != garagev1beta1.ReasonVolumeAttributesClassModifyInProgress ||
		states[1].reason != garagev1beta1.ReasonVolumeAttributesClassWaitingForBind {
		t.Fatalf("states = %#v", states)
	}
}

func TestReconcileGatewayPVCAttributesGuards(t *testing.T) {
	ctx := context.Background()
	cluster := vacEdgeGatewayCluster(ptr.To(vacGold))

	t.Run("no class desired", func(t *testing.T) {
		c := vacEdgeGatewayCluster(nil)
		r, _ := vacEdgeGatewayReconciler(t, interceptor.Funcs{}, c, true)
		if states, err := r.reconcileGatewayPVCAttributes(ctx, c); err != nil || states != nil {
			t.Fatalf("states=%v err=%v", states, err)
		}
	})
	t.Run("missing StatefulSet waits", func(t *testing.T) {
		r, _ := vacEdgeGatewayReconciler(t, interceptor.Funcs{}, cluster, false)
		states, err := r.reconcileGatewayPVCAttributes(ctx, cluster)
		if err != nil || len(states) != 1 || states[0].reason != garagev1beta1.ReasonVolumeAttributesClassWaitingForBind {
			t.Fatalf("states=%v err=%v", states, err)
		}
	})
	t.Run("claim without selector labels is refused", func(t *testing.T) {
		foreign := vacGatewayPVC(cluster, 0, true)
		foreign.Labels = nil
		var patches int
		r, _ := vacEdgeGatewayReconciler(t, interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
			patches++
			return c.Patch(ctx, obj, p, opts...)
		}}, cluster, true, foreign)
		if _, err := r.reconcileGatewayPVCAttributes(ctx, cluster); err == nil || !strings.Contains(err.Error(), "selector labels") {
			t.Fatalf("want provenance refusal, got %v", err)
		}
		if patches != 0 {
			t.Fatal("a foreign claim must not be patched")
		}
	})
	t.Run("StatefulSet not controlled by the cluster is refused", func(t *testing.T) {
		scheme := vacTestScheme(t)
		sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: gatewayWorkloadName(cluster), Namespace: vacNS}}
		fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, sts).Build()
		r := &GarageClusterReconciler{Client: fc, Scheme: scheme}
		if _, err := r.reconcileGatewayPVCAttributes(ctx, cluster); err == nil || !strings.Contains(err.Error(), "not controlled") {
			t.Fatalf("want ownership refusal, got %v", err)
		}
	})
	t.Run("unsupported API server is reported, not failed", func(t *testing.T) {
		bound := vacGatewayPVC(cluster, 0, true)
		single := vacEdgeGatewayCluster(ptr.To(vacGold))
		single.Spec.Gateway.Replicas = 1
		r, _ := vacEdgeGatewayReconciler(t, interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
			return apierrors.NewForbidden(schema.GroupResource{Resource: "persistentvolumeclaims"}, obj.GetName(), fmt.Errorf("feature gate disabled"))
		}}, single, true, bound)
		states, err := r.reconcileGatewayPVCAttributes(ctx, single)
		if err != nil || len(states) != 1 || states[0].reason != garagev1beta1.ReasonVolumeAttributesClassUnsupported {
			t.Fatalf("states=%v err=%v", states, err)
		}
	})
}

func vacChildNode(name string, cluster *garagev1beta2.GarageCluster, class *string, cond *metav1.Condition) *garagev1beta1.GarageNode {
	node := vacNode(class, nil)
	node.Name = name
	node.UID = types.UID(name + "-uid")
	node.Labels = map[string]string{labelCluster: cluster.Name, labelAppManagedBy: managedByOperatorValue}
	node.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster))}
	if cond != nil {
		cond.Type = garagev1beta1.ConditionVolumeAttributesClassApplied
		cond.LastTransitionTime = metav1.Now()
		node.Status.Conditions = []metav1.Condition{*cond}
	}
	return node
}

func TestReconcileStorageVolumeAttributesCondition(t *testing.T) {
	ctx := context.Background()
	cluster := vacAutoCluster()
	applied := &metav1.Condition{Status: metav1.ConditionTrue, Reason: garagev1beta1.ReasonVolumeAttributesClassApplied}
	infeasible := &metav1.Condition{Status: metav1.ConditionFalse, Reason: garagev1beta1.ReasonVolumeAttributesClassInfeasible}

	condition := func(fc client.Client) *metav1.Condition {
		fresh := &garagev1beta2.GarageCluster{}
		if err := fc.Get(ctx, client.ObjectKeyFromObject(cluster), fresh); err != nil {
			t.Fatal(err)
		}
		return meta.FindStatusCondition(fresh.Status.Conditions, garagev1beta1.ConditionStorageVolumeAttributesReady)
	}

	t.Run("absent when nothing requests a class", func(t *testing.T) {
		plain := vacChildNode("plain", cluster, nil, nil)
		r, fc := vacEdgeGatewayReconciler(t, interceptor.Funcs{}, cluster.DeepCopy(), false, plain)
		if err := r.reconcileStorageVolumeAttributesCondition(ctx, cluster.DeepCopy(), nil); err != nil {
			t.Fatal(err)
		}
		if condition(fc) != nil {
			t.Fatal("condition must be absent")
		}
	})
	t.Run("true when every workload applied", func(t *testing.T) {
		a := vacChildNode("a", cluster, ptr.To(vacGold), applied.DeepCopy())
		b := vacChildNode("b", cluster, ptr.To(vacGold), applied.DeepCopy())
		r, fc := vacEdgeGatewayReconciler(t, interceptor.Funcs{}, cluster.DeepCopy(), false, a, b)
		live := cluster.DeepCopy()
		if err := r.reconcileStorageVolumeAttributesCondition(ctx, live, nil); err != nil {
			t.Fatal(err)
		}
		if c := condition(fc); c == nil || c.Status != metav1.ConditionTrue {
			t.Fatalf("condition = %#v", c)
		}
	})
	t.Run("false with the most severe reason, naming failing nodes", func(t *testing.T) {
		a := vacChildNode("a", cluster, ptr.To(vacGold), applied.DeepCopy())
		b := vacChildNode("b", cluster, ptr.To(vacGold), infeasible.DeepCopy())
		c := vacChildNode("c", cluster, ptr.To(vacGold), nil)
		r, fc := vacEdgeGatewayReconciler(t, interceptor.Funcs{}, cluster.DeepCopy(), false, a, b, c)
		live := cluster.DeepCopy()
		gw := []vacClaimState{{claim: "meta-gw-0", reason: garagev1beta1.ReasonVolumeAttributesClassModifyInProgress}}
		if err := r.reconcileStorageVolumeAttributesCondition(ctx, live, gw); err != nil {
			t.Fatal(err)
		}
		got := condition(fc)
		if got == nil || got.Status != metav1.ConditionFalse || got.Reason != garagev1beta1.ReasonVolumeAttributesClassInfeasible {
			t.Fatalf("condition = %#v", got)
		}
		for _, want := range []string{"3 of 4", "b (Infeasible)", "c (pending)", "meta-gw-0"} {
			if !strings.Contains(got.Message, want) {
				t.Errorf("message %q missing %q", got.Message, want)
			}
		}
	})
	t.Run("never feeds Ready", func(t *testing.T) {
		b := vacChildNode("b", cluster, ptr.To(vacGold), infeasible.DeepCopy())
		live := cluster.DeepCopy()
		r, _ := vacEdgeGatewayReconciler(t, interceptor.Funcs{}, live, false, b)
		before := live.Status.Phase
		if err := r.reconcileStorageVolumeAttributesCondition(ctx, live, nil); err != nil {
			t.Fatal(err)
		}
		if live.Status.Phase != before || meta.FindStatusCondition(live.Status.Conditions, "Ready") != nil {
			t.Fatal("the aggregate is informational and must not touch Phase or Ready")
		}
	})
	t.Run("removes a stale condition", func(t *testing.T) {
		live := cluster.DeepCopy()
		live.Status.Conditions = []metav1.Condition{{
			Type: garagev1beta1.ConditionStorageVolumeAttributesReady, Status: metav1.ConditionFalse,
			Reason: garagev1beta1.ReasonVolumeAttributesClassInfeasible, LastTransitionTime: metav1.Now(),
		}}
		r, fc := vacEdgeGatewayReconciler(t, interceptor.Funcs{}, live.DeepCopy(), false)
		if err := r.reconcileStorageVolumeAttributesCondition(ctx, live, nil); err != nil {
			t.Fatal(err)
		}
		if condition(fc) != nil {
			t.Fatal("stale condition must be removed once no workload requests a class")
		}
	})
}

func TestReservedManagedPVCInheritsClassFromTemplate(t *testing.T) {
	ctx := context.Background()
	node := vacNode(ptr.To(vacGold), nil)
	cluster := vacCluster()
	r, fc := vacNodeReconciler(t, interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		obj.SetUID("assigned-uid") // the fake client does not assign UIDs
		return c.Create(ctx, obj, opts...)
	}}, node)
	templates := r.buildNodeVolumeClaimTemplates(node, cluster)
	var metadata *corev1.PersistentVolumeClaim
	for i := range templates {
		if templates[i].Name == metadataVolName {
			metadata = &templates[i]
		}
	}
	if metadata == nil {
		t.Fatal("no metadata template")
	}
	name := "metadata-" + node.Name + "-0"
	if err := r.reserveManagedNodePVC(ctx, node, cluster, metadata, name); err != nil {
		t.Fatal(err)
	}
	// A newly created claim carries the class from creation, so a fresh volume
	// is provisioned with it and never needs the post-bind patch.
	if got := getPVC(t, fc, name).Spec.VolumeAttributesClassName; got == nil || *got != vacGold {
		t.Fatalf("reserved claim class = %v, want %s", got, vacGold)
	}
}
