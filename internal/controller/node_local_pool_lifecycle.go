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

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// reconcileNodeLocalPools drives desired pools and safely retires pools or
// nodes that fell out of the spec. It is called even when the desired list is
// empty so removed pools can finish draining.
//
// Every phase consumes and extends one explicit reconciliation snapshot. A
// phase may stop successfully after publishing a durable progress/safety
// condition; that outcome is distinct from both advancing and returning an API
// error.
func (r *GarageClusterReconciler) reconcileNodeLocalPools(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	configHashes map[string]string,
) error {
	transition := &nodeLocalPoolLifecycleTransition{
		reconciler:   r,
		ctx:          ctx,
		cluster:      cluster,
		configHashes: configHashes,
	}
	phases := []func() nodeLocalPoolLifecyclePhaseResult{
		transition.preflight,
		transition.holdOutOfService,
		transition.publishWorkloads,
		transition.observeActors,
		transition.planActivations,
		transition.executeActivations,
		transition.materializeMembers,
		transition.retireOneMember,
		transition.projectReadiness,
	}
	for _, run := range phases {
		result := run()
		if result.Err != nil || result.Stop {
			return result.Err
		}
	}
	return nil
}
