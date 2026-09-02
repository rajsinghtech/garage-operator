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

package v1beta1

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var errReferenceGrantDenied = errors.New("reference grant denied")

const (
	garageBucketKind = "GarageBucket"
	garageKeyKind    = "GarageKey"
)

// checkReferenceGrant returns nil if a cross-namespace reference is permitted by a
// GarageReferenceGrant in the target namespace, or an error describing the missing grant.
//
// fromKind: the kind making the reference (GarageKey or GarageBucket; the
// GarageAdminToken enum value is retained for compatibility but its static
// credential path is namespace-local)
// fromNamespace: namespace of the resource making the reference
// toKind: the kind being referenced (GarageCluster, GarageBucket, GarageKey)
// toNamespace: namespace of the resource being referenced
// toName: name of the resource being referenced
//
// Same-namespace references always pass without a grant.
func checkReferenceGrant(ctx context.Context, c client.Reader, fromKind, fromNamespace, toKind, toNamespace, toName string) error {
	if fromNamespace == toNamespace {
		return nil
	}

	grants := &GarageReferenceGrantList{}
	if err := c.List(ctx, grants, client.InNamespace(toNamespace)); err != nil {
		return fmt.Errorf("failed to list GarageReferenceGrants in namespace %q: %w", toNamespace, err)
	}

	// Preserve the exact-namespace path without an additional Namespace read.
	// This retains the existing authorization behavior for installations that do
	// not use label selectors.
	for i := range grants.Items {
		if grantPermits(&grants.Items[i], fromKind, fromNamespace, toKind, toName, nil) {
			return nil
		}
	}

	if !grantsUseNamespaceSelector(grants, fromKind) {
		return referenceGrantDenied(fromKind, fromNamespace, toKind, toNamespace, toName)
	}

	// Namespace labels are authoritative policy input for selector grants. Read
	// the source Namespace only after exact grants have been ruled out, and fail
	// closed if it no longer exists or cannot be read.
	var sourceNamespace corev1.Namespace
	if err := c.Get(ctx, client.ObjectKey{Name: fromNamespace}, &sourceNamespace); err != nil {
		if apierrors.IsNotFound(err) {
			return referenceGrantDenied(fromKind, fromNamespace, toKind, toNamespace, toName)
		}
		return fmt.Errorf("failed to get source Namespace %q while evaluating GarageReferenceGrants: %w", fromNamespace, err)
	}
	for i := range grants.Items {
		if GrantPermitsForNamespace(&grants.Items[i], fromKind, fromNamespace, toKind, toName, sourceNamespace.Labels) {
			return nil
		}
	}

	return referenceGrantDenied(fromKind, fromNamespace, toKind, toNamespace, toName)
}

func referenceGrantDenied(fromKind, fromNamespace, toKind, toNamespace, toName string) error {
	return &referenceGrantDeniedError{message: fmt.Sprintf(
		"cross-namespace reference from %s %q/%q to %s %q/%q is not permitted: "+
			"create a GarageReferenceGrant in namespace %q granting %s/%q access",
		fromKind, fromNamespace, "<name>",
		toKind, toNamespace, toName,
		toNamespace, fromKind, fromNamespace,
	)}
}

// referenceGrantDeniedError preserves the established denial message while
// allowing reconcilers to distinguish a denied reference from an error while
// evaluating the grants themselves.
type referenceGrantDeniedError struct {
	message string
}

func (e *referenceGrantDeniedError) Error() string { return e.message }

func (e *referenceGrantDeniedError) Is(target error) bool {
	return target == errReferenceGrantDenied
}

// IsReferenceGrantDenied reports whether err is the deliberate fail-closed
// result for a reference that has no matching GarageReferenceGrant. Errors
// reading grants or source namespace metadata are not classified as denials.
func IsReferenceGrantDenied(err error) bool {
	return errors.Is(err, errReferenceGrantDenied)
}

// CheckReferenceGrant applies the same cross-namespace authorization during
// reconciliation as admission. This prevents persisted objects from continuing
// to mutate Garage after a grant is removed or when admission was bypassed.
func CheckReferenceGrant(ctx context.Context, c client.Reader, fromKind, fromNamespace, toKind, toNamespace, toName string) error {
	return checkReferenceGrant(ctx, c, fromKind, fromNamespace, toKind, toNamespace, toName)
}

// grantPermits reports whether a GarageReferenceGrant permits the described
// reference. A nil sourceNamespaceLabels deliberately means labels are
// unavailable, so NamespaceSelector entries cannot match.
func grantPermits(grant *GarageReferenceGrant, fromKind, fromNamespace, toKind, toName string, sourceNamespaceLabels labels.Set) bool {
	if !grantFromPermits(grant, fromKind, fromNamespace, sourceNamespaceLabels) {
		return false
	}

	// Preserve the original API contract: an omitted To list grants only the
	// resource kinds that existed when GarageReferenceGrant was introduced.
	// Newly referenceable kinds require an explicit opt-in so an old broad grant
	// cannot silently expand its authority after an operator upgrade.
	if len(grant.Spec.To) == 0 {
		return toKind == garageClusterKind || toKind == garageBucketKind
	}

	for _, t := range grant.Spec.To {
		if t.Kind == toKind && (t.Name == "" || t.Name == toName) {
			return true
		}
	}
	return false
}

func grantFromPermits(grant *GarageReferenceGrant, fromKind, fromNamespace string, sourceNamespaceLabels labels.Set) bool {
	for _, from := range grant.Spec.From {
		if from.Kind != fromKind {
			continue
		}

		// Invalid entries (both fields or neither) never authorize a request,
		// even if admission was bypassed. This is intentionally fail-closed.
		switch {
		case from.Namespace != "" && from.NamespaceSelector == nil:
			if from.Namespace == fromNamespace {
				return true
			}
		case from.Namespace == "" && from.NamespaceSelector != nil && sourceNamespaceLabels != nil:
			selector, err := metav1.LabelSelectorAsSelector(from.NamespaceSelector)
			if err == nil && selector.Matches(sourceNamespaceLabels) {
				return true
			}
		}
	}
	return false
}

func grantsUseNamespaceSelector(grants *GarageReferenceGrantList, fromKind string) bool {
	for i := range grants.Items {
		for _, from := range grants.Items[i].Spec.From {
			if from.Kind == fromKind && from.Namespace == "" && from.NamespaceSelector != nil {
				return true
			}
		}
	}
	return false
}

// GrantPermits reports whether an exact-namespace entry in this grant
// authorizes a reference. Call GrantPermitsForNamespace when source Namespace
// labels are available. Status accounting uses both forms to avoid attributing
// every reference in a destination namespace to every grant there.
func GrantPermits(grant *GarageReferenceGrant, fromKind, fromNamespace, toKind, toName string) bool {
	return grantPermits(grant, fromKind, fromNamespace, toKind, toName, nil)
}

// GrantPermitsForNamespace reports whether this exact grant authorizes a
// reference when the source Namespace's labels are known. Status accounting
// uses it alongside CheckReferenceGrant so exact-name and selector entries
// share one fail-closed matcher.
func GrantPermitsForNamespace(grant *GarageReferenceGrant, fromKind, fromNamespace, toKind, toName string, sourceNamespaceLabels map[string]string) bool {
	labelSet := labels.Set(sourceNamespaceLabels)
	if labelSet == nil {
		labelSet = labels.Set{}
	}
	return grantPermits(grant, fromKind, fromNamespace, toKind, toName, labelSet)
}
