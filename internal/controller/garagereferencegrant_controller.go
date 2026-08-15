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
	"sort"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
)

// GarageReferenceGrantReconciler reconciles GarageReferenceGrant status.
type GarageReferenceGrantReconciler struct {
	client.Client
}

// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagereferencegrants,verbs=get;list;watch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagereferencegrants/status,verbs=update;patch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagekeys,verbs=list;watch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagebuckets,verbs=list;watch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garageadmintokens,verbs=list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

func (r *GarageReferenceGrantReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	var grant garagev1beta1.GarageReferenceGrant
	if err := r.Get(ctx, req.NamespacedName, &grant); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	users, err := r.findUsers(ctx, &grant)
	if err != nil {
		log.Error(err, "failed to find grant users")
		return ctrl.Result{}, err
	}

	patch := client.MergeFrom(grant.DeepCopy())
	oldStatus := grant.Status.DeepCopy()
	grant.Status.InUseBy = users

	apimeta.SetStatusCondition(&grant.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "GrantPresent",
		Message:            "GarageReferenceGrant is present and valid",
		ObservedGeneration: grant.Generation,
	})

	inUseStatus := metav1.ConditionFalse
	inUseReason := "NoReferences"
	inUseMsg := "No resources are currently referencing through this grant"
	if len(users) > 0 {
		inUseStatus = metav1.ConditionTrue
		inUseReason = "ActiveReferences"
		inUseMsg = "One or more resources are referencing through this grant"
	}
	apimeta.SetStatusCondition(&grant.Status.Conditions, metav1.Condition{
		Type:               "InUse",
		Status:             inUseStatus,
		Reason:             inUseReason,
		Message:            inUseMsg,
		ObservedGeneration: grant.Generation,
	})

	if apiequality.Semantic.DeepEqual(*oldStatus, grant.Status) {
		return ctrl.Result{}, nil
	}

	if err := r.Status().Patch(ctx, &grant, patch); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *GarageReferenceGrantReconciler) findUsers(ctx context.Context, grant *garagev1beta1.GarageReferenceGrant) ([]garagev1beta1.ReferenceGrantUser, error) {
	var users []garagev1beta1.ReferenceGrantUser
	type namespaceLabelsResult struct {
		labels map[string]string
		found  bool
	}
	namespaceLabels := map[string]namespaceLabelsResult{}
	labelsFor := func(namespace string) (map[string]string, bool, error) {
		if cached, ok := namespaceLabels[namespace]; ok {
			return cached.labels, cached.found, nil
		}

		var sourceNamespace corev1.Namespace
		if err := r.Get(ctx, client.ObjectKey{Name: namespace}, &sourceNamespace); err != nil {
			if apierrors.IsNotFound(err) {
				namespaceLabels[namespace] = namespaceLabelsResult{}
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("get source Namespace %q: %w", namespace, err)
		}
		namespaceLabels[namespace] = namespaceLabelsResult{labels: sourceNamespace.Labels, found: true}
		return sourceNamespace.Labels, true, nil
	}
	permits := func(fromKind, fromNamespace, toKind, toName string) (bool, error) {
		if garagev1beta1.GrantPermits(grant, fromKind, fromNamespace, toKind, toName) {
			return true, nil
		}
		if !grantUsesNamespaceSelector(grant, fromKind) {
			return false, nil
		}
		labels, found, err := labelsFor(fromNamespace)
		if err != nil || !found {
			return false, err
		}
		return garagev1beta1.GrantPermitsForNamespace(grant, fromKind, fromNamespace, toKind, toName, labels), nil
	}
	add := func(kind, name, namespace string, matched *bool) {
		if *matched {
			return
		}
		users = append(users, garagev1beta1.ReferenceGrantUser{Kind: kind, Name: name, Namespace: namespace})
		*matched = true
	}

	var keys garagev1beta1.GarageKeyList
	if err := r.List(ctx, &keys); err != nil {
		return nil, err
	}
	for _, k := range keys.Items {
		matched := false
		if crossNSRefsGrant(&k.Spec.ClusterRef, k.Namespace, grant) {
			allowed, err := permits(garageKeyKind, k.Namespace, "GarageCluster", k.Spec.ClusterRef.Name)
			if err != nil {
				return nil, err
			}
			if allowed {
				add(garageKeyKind, k.Name, k.Namespace, &matched)
			}
		}
		for _, bp := range k.Spec.BucketPermissions {
			if bp.BucketRef != nil {
				ns := bp.BucketRef.Namespace
				if ns == "" {
					ns = k.Namespace
				}
				if ns == grant.Namespace && k.Namespace != grant.Namespace {
					allowed, err := permits(garageKeyKind, k.Namespace, "GarageBucket", bp.BucketRef.Name)
					if err != nil {
						return nil, err
					}
					if allowed {
						add(garageKeyKind, k.Name, k.Namespace, &matched)
						break
					}
				}
			}
		}
	}

	var buckets garagev1beta1.GarageBucketList
	if err := r.List(ctx, &buckets); err != nil {
		return nil, err
	}
	for _, b := range buckets.Items {
		matched := false
		if crossNSRefsGrant(&b.Spec.ClusterRef, b.Namespace, grant) {
			allowed, err := permits("GarageBucket", b.Namespace, "GarageCluster", b.Spec.ClusterRef.Name)
			if err != nil {
				return nil, err
			}
			if allowed {
				add("GarageBucket", b.Name, b.Namespace, &matched)
			}
		}
		for _, permission := range b.Spec.KeyPermissions {
			ns := permission.KeyRef.Namespace
			if ns == "" {
				ns = b.Namespace
			}
			if ns == grant.Namespace && b.Namespace != grant.Namespace {
				allowed, err := permits("GarageBucket", b.Namespace, garageKeyKind, permission.KeyRef.Name)
				if err != nil {
					return nil, err
				}
				if allowed {
					add("GarageBucket", b.Name, b.Namespace, &matched)
					break
				}
			}
		}
	}

	var tokens garagev1beta1.GarageAdminTokenList
	if err := r.List(ctx, &tokens); err != nil {
		return nil, err
	}
	for _, tok := range tokens.Items {
		if crossNSRefsGrant(&tok.Spec.ClusterRef, tok.Namespace, grant) {
			allowed, err := permits(kindGarageAdminToken, tok.Namespace, "GarageCluster", tok.Spec.ClusterRef.Name)
			if err != nil {
				return nil, err
			}
			if allowed {
				users = append(users, garagev1beta1.ReferenceGrantUser{Kind: kindGarageAdminToken, Name: tok.Name, Namespace: tok.Namespace})
			}
		}
	}

	sort.Slice(users, func(i, j int) bool {
		if users[i].Kind != users[j].Kind {
			return users[i].Kind < users[j].Kind
		}
		if users[i].Namespace != users[j].Namespace {
			return users[i].Namespace < users[j].Namespace
		}
		return users[i].Name < users[j].Name
	})

	return users, nil
}

func grantUsesNamespaceSelector(grant *garagev1beta1.GarageReferenceGrant, fromKind string) bool {
	for _, from := range grant.Spec.From {
		if from.Kind == fromKind && from.Namespace == "" && from.NamespaceSelector != nil {
			return true
		}
	}
	return false
}

func grantHasNamespaceSelector(grant *garagev1beta1.GarageReferenceGrant) bool {
	for _, from := range grant.Spec.From {
		if from.Namespace == "" && from.NamespaceSelector != nil {
			return true
		}
	}
	return false
}

// namespaceSelectorGrantRequests returns every grant with a namespace
// selector. A Namespace label update can add or remove a match, so checking
// only selectors that match the post-update labels would leave stale inUseBy
// entries behind.
func namespaceSelectorGrantRequests(ctx context.Context, c client.Client) []reconcile.Request {
	var grants garagev1beta1.GarageReferenceGrantList
	if err := c.List(ctx, &grants); err != nil {
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(grants.Items))
	for i := range grants.Items {
		if !grantHasNamespaceSelector(&grants.Items[i]) {
			continue
		}
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&grants.Items[i])})
	}
	return reqs
}

// crossNSRefsGrant returns true when the ClusterReference targets the grant's namespace
// from a different namespace (i.e., is a cross-namespace reference governed by a grant).
func crossNSRefsGrant(ref *garagev1beta1.ClusterReference, resourceNS string, grant *garagev1beta1.GarageReferenceGrant) bool {
	if ref == nil {
		return false
	}
	targetNS := ref.Namespace
	if targetNS == "" {
		targetNS = resourceNS
	}
	return targetNS == grant.Namespace && resourceNS != grant.Namespace
}

// grantTargetNamespaces returns the set of namespaces a changed key/bucket/token
// references cross-namespace. A GarageReferenceGrant only governs references that
// land in its own namespace, so these are the only namespaces whose grants can be
// affected by a change to obj. Same-namespace references are skipped (no grant
// applies). The logic mirrors crossNSRefsGrant / findUsers so the watch trigger
// and the reconcile scan stay in agreement.
func grantTargetNamespaces(obj client.Object) []string {
	srcNS := obj.GetNamespace()
	seen := map[string]bool{}
	var out []string
	add := func(refNS string) {
		if refNS == "" {
			refNS = srcNS
		}
		if refNS == srcNS || seen[refNS] {
			return
		}
		seen[refNS] = true
		out = append(out, refNS)
	}

	switch o := obj.(type) {
	case *garagev1beta1.GarageKey:
		add(o.Spec.ClusterRef.Namespace)
		for _, bp := range o.Spec.BucketPermissions {
			if bp.BucketRef != nil {
				add(bp.BucketRef.Namespace)
			}
		}
	case *garagev1beta1.GarageBucket:
		add(o.Spec.ClusterRef.Namespace)
		for _, permission := range o.Spec.KeyPermissions {
			add(permission.KeyRef.Namespace)
		}
	case *garagev1beta1.GarageAdminToken:
		add(o.Spec.ClusterRef.Namespace)
	}
	return out
}

// SetupWithManager wires up the controller.
func (r *GarageReferenceGrantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	mapToGrants := func(ctx context.Context, obj client.Object) []reconcile.Request {
		// A grant in namespace N only governs cross-namespace references INTO N.
		// So a changed key/bucket/token can only affect grants living in the
		// namespace(s) it actually targets — list just those, never cluster-wide.
		var reqs []reconcile.Request
		seen := map[string]bool{}
		for _, ns := range grantTargetNamespaces(obj) {
			var grants garagev1beta1.GarageReferenceGrantList
			if err := mgr.GetClient().List(ctx, &grants, client.InNamespace(ns)); err != nil {
				continue
			}
			for _, g := range grants.Items {
				key := g.Namespace + "/" + g.Name
				if seen[key] {
					continue
				}
				seen[key] = true
				reqs = append(reqs, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: g.Name, Namespace: g.Namespace},
				})
			}
		}
		return reqs
	}
	mapNamespaceToSelectorGrants := func(ctx context.Context, _ client.Object) []reconcile.Request {
		return namespaceSelectorGrantRequests(ctx, mgr.GetClient())
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&garagev1beta1.GarageReferenceGrant{}).
		Watches(&garagev1beta1.GarageKey{}, handler.EnqueueRequestsFromMapFunc(mapToGrants),
			builder.WithPredicates()).
		Watches(&garagev1beta1.GarageBucket{}, handler.EnqueueRequestsFromMapFunc(mapToGrants),
			builder.WithPredicates()).
		Watches(&garagev1beta1.GarageAdminToken{}, handler.EnqueueRequestsFromMapFunc(mapToGrants),
			builder.WithPredicates()).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(mapNamespaceToSelectorGrants),
			builder.WithPredicates()).
		Complete(r)
}
