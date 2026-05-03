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
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// checkReferenceGrant returns nil if a cross-namespace reference is permitted by a
// GarageReferenceGrant in the target namespace, or an error describing the missing grant.
//
// fromKind: the kind making the reference (GarageKey, GarageBucket, GarageAdminToken)
// fromNamespace: namespace of the resource making the reference
// toKind: the kind being referenced (GarageCluster, GarageBucket)
// toNamespace: namespace of the resource being referenced
// toName: name of the resource being referenced
//
// Same-namespace references always pass without a grant.
func checkReferenceGrant(ctx context.Context, c client.Client, fromKind, fromNamespace, toKind, toNamespace, toName string) error {
	if fromNamespace == toNamespace {
		return nil
	}

	grants := &GarageReferenceGrantList{}
	if err := c.List(ctx, grants, client.InNamespace(toNamespace)); err != nil {
		return fmt.Errorf("failed to list GarageReferenceGrants in namespace %q: %w", toNamespace, err)
	}

	for i := range grants.Items {
		if grantPermits(&grants.Items[i], fromKind, fromNamespace, toKind, toName) {
			return nil
		}
	}

	return fmt.Errorf(
		"cross-namespace reference from %s %q/%q to %s %q/%q is not permitted: "+
			"create a GarageReferenceGrant in namespace %q granting %s/%q access",
		fromKind, fromNamespace, "<name>",
		toKind, toNamespace, toName,
		toNamespace, fromKind, fromNamespace,
	)
}

// grantPermits reports whether a GarageReferenceGrant permits the described reference.
func grantPermits(grant *GarageReferenceGrant, fromKind, fromNamespace, toKind, toName string) bool {
	fromMatched := false
	for _, f := range grant.Spec.From {
		if f.Kind == fromKind && f.Namespace == fromNamespace {
			fromMatched = true
			break
		}
	}
	if !fromMatched {
		return false
	}

	// No To entries means all resources in this namespace are accessible.
	if len(grant.Spec.To) == 0 {
		return true
	}

	for _, t := range grant.Spec.To {
		if t.Kind == toKind && (t.Name == "" || t.Name == toName) {
			return true
		}
	}
	return false
}
