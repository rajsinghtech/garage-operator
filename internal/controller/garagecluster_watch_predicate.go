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
	"maps"
	"slices"

	"k8s.io/apimachinery/pkg/api/equality"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// garageClusterPrimaryPredicate filters the GarageCluster controller's own
// watch so that status-only writes do not re-enter Reconcile.
//
// Every status pass refreshes live projections that change continuously
// (status.storageStats bytes, status.resyncQueueLength, block-error times,
// health counters). With an unfiltered primary watch each such write queued
// another reconcile, so a busy or refilling cluster reconciled back to back
// and the RequeueAfter pacing never applied. This mirrors the GarageNode
// controller, whose primary watch has used GenerationChangedPredicate since
// its status.lastSeen churn was fixed.
//
// An update passes when any of these change:
//   - metadata.generation (spec edits);
//   - labels or annotations (one-shot operation annotations such as
//     connect-nodes, purge-cluster-layout and skip-dead-nodes, and label-based
//     selection);
//   - finalizers or deletionTimestamp (deletion and finalization);
//   - the cross-controller coordination records status.storageRollout and
//     status.storageDrain. The GarageNode controller writes these on the
//     parent (lost-source transfer, node drain proof/clear/abort), and the
//     parent must observe the transfer or release promptly instead of waiting
//     for its periodic requeue. The drain proof's QueueLength and ErrorCount
//     are diagnostic counters that change on every pass, so they are ignored.
//
// Create, Delete and Generic events always pass. Every reconcile path that
// returns success schedules its own requeue (see Reconcile), so nothing
// depends on the watch firing after the controller's own status write.
func garageClusterPrimaryPredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldCluster, oldOK := e.ObjectOld.(*garagev1beta2.GarageCluster)
			newCluster, newOK := e.ObjectNew.(*garagev1beta2.GarageCluster)
			if !oldOK || !newOK {
				return true
			}
			return garageClusterUpdateNeedsReconcile(oldCluster, newCluster)
		},
	}
}

func garageClusterUpdateNeedsReconcile(oldCluster, newCluster *garagev1beta2.GarageCluster) bool {
	if oldCluster.Generation != newCluster.Generation {
		return true
	}
	if !maps.Equal(oldCluster.Labels, newCluster.Labels) ||
		!maps.Equal(oldCluster.Annotations, newCluster.Annotations) ||
		!slices.Equal(oldCluster.Finalizers, newCluster.Finalizers) ||
		!oldCluster.DeletionTimestamp.Equal(newCluster.DeletionTimestamp) {
		return true
	}
	if !equality.Semantic.DeepEqual(oldCluster.Status.StorageRollout, newCluster.Status.StorageRollout) {
		return true
	}
	return !equality.Semantic.DeepEqual(
		storageDrainCoordinationRecord(oldCluster.Status.StorageDrain),
		storageDrainCoordinationRecord(newCluster.Status.StorageDrain),
	)
}

// storageDrainCoordinationRecord drops the per-pass diagnostic counters from
// the drain record so that only actor, transaction, target and proof-evidence
// changes wake the parent.
func storageDrainCoordinationRecord(drain *garagev1beta2.StorageDrainStatus) *garagev1beta2.StorageDrainStatus {
	if drain == nil {
		return nil
	}
	record := drain.DeepCopy()
	record.QueueLength = 0
	record.ErrorCount = 0
	return record
}

// requeueSuccessfulGarageClusterResult keeps a live GarageCluster on a
// periodic reconcile when a path returned success without scheduling one.
// Before the primary watch was filtered, such a path was usually re-entered
// by the watch event of its own status write; now it must say when to run
// again. Deleted objects, and objects whose deletion has started (finalization
// returns explicit results or errors), are left alone.
func (r *GarageClusterReconciler) requeueSuccessfulGarageClusterResult(
	ctx context.Context,
	req ctrl.Request,
	result ctrl.Result,
	err error,
) (ctrl.Result, error) {
	if err != nil || !result.IsZero() {
		return result, err
	}
	cluster := &garagev1beta2.GarageCluster{}
	if getErr := r.Get(ctx, req.NamespacedName, cluster); getErr != nil {
		return result, nil
	}
	if !cluster.DeletionTimestamp.IsZero() {
		return result, nil
	}
	return ctrl.Result{RequeueAfter: RequeueAfterError}, nil
}
