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

package cosi

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagecontroller "github.com/rajsinghtech/garage-operator/internal/controller"
)

// GarageProtectionFinalizer is independent from COSI's shared protection
// finalizer. The upstream controller may remove its finalizer as soon as its
// bookkeeping is complete; this one keeps the object alive until Garage-side
// cleanup has completed.
const GarageProtectionFinalizer = "garage.rajsingh.info/cosi-protection"

// recordFinalizationRetry persists the bounded-retry counter shared by the
// native and COSI cleanup paths. Callers must handle a NotFound error as a
// completed deletion race.
func recordFinalizationRetry(ctx context.Context, c client.Client, object client.Object) (int, error) {
	originalUID := object.GetUID()
	for attempt := 0; attempt < garagecontroller.StatusUpdateMaxRetries; attempt++ {
		base, ok := object.DeepCopyObject().(client.Object)
		if !ok {
			return 0, fmt.Errorf("cannot snapshot finalization retry for %T", object)
		}
		garagecontroller.IncrementFinalizationRetryCount(object)
		count := garagecontroller.GetFinalizationRetryCount(object)
		if err := c.Patch(ctx, object, client.MergeFrom(base)); err == nil {
			return count, nil
		} else if !apierrors.IsConflict(err) {
			return count, err
		}

		if attempt == garagecontroller.StatusUpdateMaxRetries-1 {
			return count, fmt.Errorf("failed to update finalization retry after %d conflicts", garagecontroller.StatusUpdateMaxRetries)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(object), object); err != nil {
			return count, fmt.Errorf("re-fetch finalization object after conflict: %w", err)
		}
		if originalUID != "" && object.GetUID() != originalUID {
			return count, fmt.Errorf("refusing to retry finalization counter across object recreation: UID changed from %q to %q", originalUID, object.GetUID())
		}
	}
	return 0, fmt.Errorf("finalization retry update exhausted for %T", object)
}
