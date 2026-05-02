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
	"sort"

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

	if err := r.Status().Patch(ctx, &grant, patch); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *GarageReferenceGrantReconciler) findUsers(ctx context.Context, grant *garagev1beta1.GarageReferenceGrant) ([]garagev1beta1.ReferenceGrantUser, error) {
	var users []garagev1beta1.ReferenceGrantUser

	var keys garagev1beta1.GarageKeyList
	if err := r.List(ctx, &keys); err != nil {
		return nil, err
	}
	for _, k := range keys.Items {
		if crossNSRefsGrant(&k.Spec.ClusterRef, k.Namespace, grant) {
			users = append(users, garagev1beta1.ReferenceGrantUser{Kind: "GarageKey", Name: k.Name, Namespace: k.Namespace})
			continue
		}
		for _, bp := range k.Spec.BucketPermissions {
			if bp.BucketRef != nil {
				ns := bp.BucketRef.Namespace
				if ns == "" {
					ns = k.Namespace
				}
				if ns == grant.Namespace && k.Namespace != grant.Namespace {
					users = append(users, garagev1beta1.ReferenceGrantUser{Kind: "GarageKey", Name: k.Name, Namespace: k.Namespace})
					break
				}
			}
		}
	}

	var buckets garagev1beta1.GarageBucketList
	if err := r.List(ctx, &buckets); err != nil {
		return nil, err
	}
	for _, b := range buckets.Items {
		if crossNSRefsGrant(&b.Spec.ClusterRef, b.Namespace, grant) {
			users = append(users, garagev1beta1.ReferenceGrantUser{Kind: "GarageBucket", Name: b.Name, Namespace: b.Namespace})
		}
	}

	var tokens garagev1beta1.GarageAdminTokenList
	if err := r.List(ctx, &tokens); err != nil {
		return nil, err
	}
	for _, tok := range tokens.Items {
		if crossNSRefsGrant(&tok.Spec.ClusterRef, tok.Namespace, grant) {
			users = append(users, garagev1beta1.ReferenceGrantUser{Kind: "GarageAdminToken", Name: tok.Name, Namespace: tok.Namespace})
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

// SetupWithManager wires up the controller.
func (r *GarageReferenceGrantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	mapToGrants := func(ctx context.Context, obj client.Object) []reconcile.Request {
		var grants garagev1beta1.GarageReferenceGrantList
		if err := mgr.GetClient().List(ctx, &grants); err != nil {
			return nil
		}
		reqs := make([]reconcile.Request, len(grants.Items))
		for i, g := range grants.Items {
			reqs[i] = reconcile.Request{
				NamespacedName: types.NamespacedName{Name: g.Name, Namespace: g.Namespace},
			}
		}
		return reqs
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&garagev1beta1.GarageReferenceGrant{}).
		Watches(&garagev1beta1.GarageKey{}, handler.EnqueueRequestsFromMapFunc(mapToGrants),
			builder.WithPredicates()).
		Watches(&garagev1beta1.GarageBucket{}, handler.EnqueueRequestsFromMapFunc(mapToGrants),
			builder.WithPredicates()).
		Watches(&garagev1beta1.GarageAdminToken{}, handler.EnqueueRequestsFromMapFunc(mapToGrants),
			builder.WithPredicates()).
		Complete(r)
}
