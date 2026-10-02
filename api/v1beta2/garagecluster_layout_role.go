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

package v1beta2

import (
	"fmt"

	"k8s.io/apimachinery/pkg/api/equality"
)

// purgeClusterLayoutAnnotation requests (and, until consumed, evidences) a
// coordinated replication-factor migration. It mirrors
// v1beta1.AnnotationPurgeClusterLayout, which this package cannot import.
const purgeClusterLayoutAnnotation = "garage.rajsingh.info/purge-cluster-layout"

// Factor-migration phases that end the state machine; any other non-empty
// phase means a multi-step layout transaction is in flight.
const (
	factorMigrationPhaseCompleted = "Completed"
	factorMigrationPhaseFailed    = "Failed"
)

// EffectiveLayoutSiteRole returns the layout role this site plays. An unset
// layoutManagement.siteRole is Writer, the behavior of every release before the
// field existed.
func (c *GarageCluster) EffectiveLayoutSiteRole() LayoutSiteRole {
	if c == nil || c.Spec.LayoutManagement == nil || c.Spec.LayoutManagement.SiteRole == "" {
		return LayoutSiteRoleWriter
	}
	return c.Spec.LayoutManagement.SiteRole
}

// IsLayoutFollower reports whether this site must never change the shared
// Garage layout (layoutManagement.siteRole: Follower).
func (c *GarageCluster) IsLayoutFollower() bool {
	return c.EffectiveLayoutSiteRole() == LayoutSiteRoleFollower
}

// layoutTransactionInFlight names the multi-step layout transaction recorded in
// the cluster's status, or "" when none is active. A Follower could not finish
// any of these, so a Writer must not be demoted while one runs.
func layoutTransactionInFlight(cluster *GarageCluster) string {
	switch {
	case cluster == nil:
		return ""
	case cluster.Status.StorageDrain != nil:
		return fmt.Sprintf("status.storageDrain transaction %q", cluster.Status.StorageDrain.TransactionID)
	case cluster.Status.StorageRollout != nil:
		return "status.storageRollout managed pod replacement"
	case cluster.Annotations[purgeClusterLayoutAnnotation] != "":
		return "replication-factor migration (annotation " + purgeClusterLayoutAnnotation + ")"
	case cluster.Status.FactorMigration != nil && cluster.Status.FactorMigration.Phase != "" &&
		cluster.Status.FactorMigration.Phase != factorMigrationPhaseCompleted &&
		cluster.Status.FactorMigration.Phase != factorMigrationPhaseFailed:
		return fmt.Sprintf("status.factorMigration in phase %s", cluster.Status.FactorMigration.Phase)
	}
	return ""
}

// validateLayoutSiteRoleUpdate guards layoutManagement.siteRole transitions
// against the OLD object's status (CEL cannot read status or the previous spec):
//
//   - Writer -> Follower is rejected while a drain, managed-pod rollout, or
//     factor migration is active: those are multi-step layout transactions that
//     a Follower, which performs no layout writes, could never finish.
//   - Follower -> Writer (promotion) is always allowed, because failover must
//     work when the old writer is gone, but warns that the previous writer must
//     be demoted first. There is deliberately no acknowledgement protocol.
//   - Changing spec.replication on a Follower only warns: the replication
//     factor and zone redundancy live in the shared layout and are changed on
//     the writer site. The controller reports AwaitingLayoutWriter with reason
//     ReplicationChange.
func validateLayoutSiteRoleUpdate(oldCluster, newCluster *GarageCluster) ([]string, error) {
	oldRole, newRole := oldCluster.EffectiveLayoutSiteRole(), newCluster.EffectiveLayoutSiteRole()
	var warnings []string
	switch {
	case oldRole == LayoutSiteRoleWriter && newRole == LayoutSiteRoleFollower:
		if tx := layoutTransactionInFlight(oldCluster); tx != "" {
			return nil, fmt.Errorf(
				"layoutManagement.siteRole cannot change from Writer to Follower while a layout transaction is active (%s): a Follower performs no layout writes and could not finish it; wait for it to complete, then demote",
				tx)
		}
	case oldRole == LayoutSiteRoleFollower && newRole == LayoutSiteRoleWriter:
		warnings = append(warnings,
			"promoting this site to layout Writer: make sure the previous writer site has been demoted to Follower (or is permanently gone) first; two Writers can commit conflicting layout versions and break the Garage cluster")
	}
	if newRole == LayoutSiteRoleFollower &&
		!equality.Semantic.DeepEqual(oldCluster.Spec.Replication, newCluster.Spec.Replication) {
		warnings = append(warnings,
			"spec.replication changed on a layout Follower site: the replication factor and zone redundancy are part of the shared Garage layout and are changed on the Writer site; this site will report AwaitingLayoutWriter (reason ReplicationChange) until the Writer applies it")
	}
	return warnings, nil
}
