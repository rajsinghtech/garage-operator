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

package garage

import (
	"context"
	"errors"
	"fmt"
)

// ErrLayoutWritesDisabled is returned by every Client method that stages,
// applies, reverts, or otherwise mutates the shared Garage layout when the
// context carries the layout-write-disabled marker (WithLayoutWritesDisabled).
// The operator sets the marker for a GarageCluster whose
// layoutManagement.siteRole is Follower, and for any object whose resolved
// layout owner is such a site. Callers treat it as a pending state, never as a
// failure, and must not advance a state machine or remove a finalizer on it.
var ErrLayoutWritesDisabled = errors.New("garage layout writes are disabled on this follower site")

// ErrLayoutPending marks a transient layout-safety wait: the caller must retry
// later and must not treat the state as a failure. The operator's controller
// package aliases it as errLayoutMutationPending, and an ErrLayoutWritesDisabled
// error matches it too, so every existing "pending, requeue" branch handles a
// refused follower write without a special case.
var ErrLayoutPending = errors.New("garage layout mutation pending")

// layoutWritesDisabledError is returned by guardLayoutWrite. It matches both
// ErrLayoutWritesDisabled and ErrLayoutPending under errors.Is.
type layoutWritesDisabledError struct{ detail string }

func (e *layoutWritesDisabledError) Error() string {
	return ErrLayoutWritesDisabled.Error() + ": " + e.detail
}

func (e *layoutWritesDisabledError) Is(target error) bool {
	return target == ErrLayoutWritesDisabled || target == ErrLayoutPending
}

// LayoutWriteOperation names a guarded Client method. The set is closed: the
// inventory test in the controller package fails when a call to any of these
// appears outside its allow-list.
const (
	LayoutOpUpdate        = "UpdateClusterLayout"
	LayoutOpUpdateParams  = "UpdateClusterLayoutWithParams"
	LayoutOpApply         = "ApplyClusterLayout"
	LayoutOpApplyStaged   = "ApplyStagedLayoutChanges"
	LayoutOpRevert        = "RevertClusterLayout"
	LayoutOpSkipDeadNodes = "ClusterLayoutSkipDeadNodes"
)

// LayoutWriteGuard is the marker WithLayoutWritesDisabled stores in a context.
type LayoutWriteGuard struct {
	// Cluster identifies the site for logs and metrics ("namespace/name").
	Cluster string
	// Reason is a short human-readable explanation, included in the error.
	Reason string
	// OnBlocked, when non-nil, is called with the guarded operation name each
	// time a write is refused. It must not block.
	OnBlocked func(operation string)
}

type layoutWriteGuardKey struct{}

// WithLayoutWritesDisabled returns a context in which every layout-writing
// Client method fails with ErrLayoutWritesDisabled before making a request.
func WithLayoutWritesDisabled(ctx context.Context, guard LayoutWriteGuard) context.Context {
	return context.WithValue(ctx, layoutWriteGuardKey{}, guard)
}

// LayoutWritesDisabled reports whether ctx carries the follower marker.
func LayoutWritesDisabled(ctx context.Context) bool {
	_, ok := ctx.Value(layoutWriteGuardKey{}).(LayoutWriteGuard)
	return ok
}

// guardLayoutWrite is the first statement of every layout-writing method.
func guardLayoutWrite(ctx context.Context, operation string) error {
	guard, ok := ctx.Value(layoutWriteGuardKey{}).(LayoutWriteGuard)
	if !ok {
		return nil
	}
	if guard.OnBlocked != nil {
		guard.OnBlocked(operation)
	}
	detail := operation
	if guard.Cluster != "" {
		detail = fmt.Sprintf("%s for %s", operation, guard.Cluster)
	}
	if guard.Reason != "" {
		detail = fmt.Sprintf("%s (%s)", detail, guard.Reason)
	}
	return &layoutWritesDisabledError{detail: detail}
}
