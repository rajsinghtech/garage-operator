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
	"encoding/json"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// garageOperatorFieldManager is deliberately stable across controller
// restarts and image versions. It is the owner of the metadata keys emitted by
// the operator's generated-resource reconcilers.
const garageOperatorFieldManager = "garage-operator"

// The operator historically used controller-runtime's default user agent for
// Update calls. The released image is /manager, so the apiserver records
// "manager" as the Update manager. Keep the other names used by local and
// older deployments here as well; this list is intentionally explicit so a
// foreign Update manager is never forcefully adopted during migration.
var legacyGarageOperatorUpdateManagers = map[string]struct{}{
	"manager":                            {},
	operatorName:                         {},
	"garage-operator-controller-manager": {},
}

// applyOwnedMetadata applies only the labels and annotations declared by the
// operator. Omitting a key from a subsequent apply releases it from this
// field manager, allowing the apiserver to prune it while retaining keys
// owned by another manager.
//
// Objects updated by releases before SSA may still have an operation=Update
// entry. The first apply cannot prune fields that are not yet owned by the
// SSA manager. To migrate those objects, first force-claim only the
// key-granular labels and annotations attributed to the legacy operator
// manager, then perform the real sparse apply. Foreign keys are not included
// in that migration patch and therefore remain untouched.
func applyOwnedMetadata(ctx context.Context, c client.Client, object client.Object, desired metav1.Object) error {
	if object == nil || desired == nil {
		return fmt.Errorf("applying owned metadata requires non-nil object and desired metadata")
	}
	if !metadataNeedsApply(object, desired) {
		return nil
	}

	if !hasOwnedMetadataApplyEntry(object) {
		legacyLabels, legacyAnnotations := legacyOwnedMetadata(object)
		if len(legacyLabels) != 0 || len(legacyAnnotations) != 0 {
			patch, err := metadataApplyPatch(c, object, legacyLabels, legacyAnnotations)
			if err != nil {
				return err
			}
			if err := c.Patch(
				ctx,
				object,
				client.RawPatch(types.ApplyPatchType, patch),
				client.FieldOwner(garageOperatorFieldManager),
				client.ForceOwnership,
			); err != nil {
				return fmt.Errorf("migrating legacy metadata ownership for %s/%s: %w", object.GetNamespace(), object.GetName(), err)
			}

			deleteLabels := metadataKeysNotPresent(legacyLabels, desired.GetLabels())
			deleteAnnotations := metadataKeysNotPresent(legacyAnnotations, desired.GetAnnotations())
			if len(deleteLabels) != 0 || len(deleteAnnotations) != 0 {
				patch, err := metadataApplyDeletePatch(c, object, deleteLabels, deleteAnnotations)
				if err != nil {
					return err
				}
				if err := c.Patch(
					ctx,
					object,
					client.RawPatch(types.ApplyPatchType, patch),
					client.FieldOwner(garageOperatorFieldManager),
					client.ForceOwnership,
				); err != nil {
					return fmt.Errorf("pruning legacy metadata for %s/%s: %w", object.GetNamespace(), object.GetName(), err)
				}
			}
		}
	}

	labels := desired.GetLabels()
	annotations := desired.GetAnnotations()
	patch, err := metadataApplyPatch(c, object, labels, annotations)
	if err != nil {
		return err
	}
	if err := c.Patch(
		ctx,
		object,
		client.RawPatch(types.ApplyPatchType, patch),
		client.FieldOwner(garageOperatorFieldManager),
		client.ForceOwnership,
	); err != nil {
		return fmt.Errorf("applying owned metadata for %s/%s: %w", object.GetNamespace(), object.GetName(), err)
	}
	return nil
}

func hasOwnedMetadataApplyEntry(object metav1.Object) bool {
	for _, entry := range object.GetManagedFields() {
		if entry.Manager == garageOperatorFieldManager &&
			entry.Operation == metav1.ManagedFieldsOperationApply &&
			entry.Subresource == "" {
			return true
		}
	}
	return false
}

func metadataNeedsApply(object metav1.Object, desired metav1.Object) bool {
	if hasOwnedMetadataApplyEntry(object) {
		labels, annotations, labelsMapOwned, annotationsMapOwned := appliedOwnedMetadata(object)
		return metadataMapNeedsApply(object.GetLabels(), desired.GetLabels(), labels, labelsMapOwned) ||
			metadataMapNeedsApply(object.GetAnnotations(), desired.GetAnnotations(), annotations, annotationsMapOwned)
	}

	legacyLabels, legacyAnnotations := legacyOwnedMetadata(object)
	if len(legacyLabels) != 0 || len(legacyAnnotations) != 0 {
		return true
	}

	// Objects without managed fields are common in fake clients and in clusters
	// that have managedFields disabled. Compare only the keys the operator is
	// asking for so foreign metadata does not turn a no-op reconcile into a
	// write. Once a field is actually changed, the apply below establishes the
	// new manager's ownership.
	return metadataValuesDiffer(object.GetLabels(), desired.GetLabels()) ||
		metadataValuesDiffer(object.GetAnnotations(), desired.GetAnnotations())
}

func metadataValuesDiffer(current, desired map[string]string) bool {
	for key, value := range desired {
		if current[key] != value {
			return true
		}
	}
	return false
}

func metadataMapNeedsApply(current, desired, owned map[string]string, mapOwned bool) bool {
	if mapOwned {
		if len(current) != len(desired) {
			return true
		}
		for key, value := range desired {
			if current[key] != value {
				return true
			}
		}
		return false
	}

	for key, value := range owned {
		if desiredValue, ok := desired[key]; !ok || desiredValue != value {
			return true
		}
	}
	for key, value := range desired {
		if ownedValue, ok := owned[key]; ok {
			if ownedValue != value {
				return true
			}
			continue
		}
		if current[key] != value {
			return true
		}
	}
	return false
}

func metadataApplyPatch(c client.Client, object client.Object, labels, annotations map[string]string) ([]byte, error) {
	gvk, err := c.GroupVersionKindFor(object)
	if err != nil {
		return nil, fmt.Errorf("resolving GVK for %T: %w", object, err)
	}
	metadata := map[string]any{
		"name": object.GetName(),
	}
	if namespace := object.GetNamespace(); namespace != "" {
		metadata["namespace"] = namespace
	}
	// Leave an empty map out of the patch. An omitted field is the SSA signal
	// to release the keys previously owned by this manager; an explicit empty
	// map can claim the map itself on some Kubernetes schema versions.
	if len(labels) != 0 {
		metadata["labels"] = labels
	}
	if len(annotations) != 0 {
		metadata["annotations"] = annotations
	}
	return json.Marshal(map[string]any{
		"apiVersion": gvk.GroupVersion().String(),
		"kind":       gvk.Kind,
		"metadata":   metadata,
	})
}

func metadataApplyDeletePatch(c client.Client, object client.Object, labels, annotations map[string]string) ([]byte, error) {
	gvk, err := c.GroupVersionKindFor(object)
	if err != nil {
		return nil, fmt.Errorf("resolving GVK for %T: %w", object, err)
	}
	metadata := map[string]any{
		"name": object.GetName(),
	}
	if namespace := object.GetNamespace(); namespace != "" {
		metadata["namespace"] = namespace
	}
	if len(labels) != 0 {
		values := make(map[string]any, len(labels))
		for key := range labels {
			values[key] = nil
		}
		metadata["labels"] = values
	}
	if len(annotations) != 0 {
		values := make(map[string]any, len(annotations))
		for key := range annotations {
			values[key] = nil
		}
		metadata["annotations"] = values
	}
	return json.Marshal(map[string]any{
		"apiVersion": gvk.GroupVersion().String(),
		"kind":       gvk.Kind,
		"metadata":   metadata,
	})
}

func metadataKeysNotPresent(owned, desired map[string]string) map[string]string {
	if len(owned) == 0 {
		return nil
	}
	missing := make(map[string]string)
	for key, value := range owned {
		if _, ok := desired[key]; !ok {
			missing[key] = value
		}
	}
	return missing
}

// legacyOwnedMetadata returns only values whose individual metadata keys are
// recorded under a legacy operator Update entry. Map-level ownership is not
// migrated because it cannot distinguish an old operator key from a foreign
// key; those objects remain safe and can be explicitly migrated by an
// administrator after reviewing their managedFields.
func legacyOwnedMetadata(object metav1.Object) (map[string]string, map[string]string) {
	labels := map[string]string{}
	annotations := map[string]string{}
	for _, entry := range object.GetManagedFields() {
		if entry.Operation != metav1.ManagedFieldsOperationUpdate || entry.Subresource != "" {
			continue
		}
		if _, ok := legacyGarageOperatorUpdateManagers[entry.Manager]; !ok || entry.FieldsV1 == nil {
			continue
		}

		var fields map[string]json.RawMessage
		if err := json.Unmarshal(entry.FieldsV1.GetRawBytes(), &fields); err != nil {
			continue
		}
		metadata, ok := rawObjectField(fields, "f:metadata")
		if !ok {
			continue
		}
		copyOwnedMetadataMap(metadata, "labels", object.GetLabels(), labels)
		copyOwnedMetadataMap(metadata, "annotations", object.GetAnnotations(), annotations)
	}
	return labels, annotations
}

func appliedOwnedMetadata(object metav1.Object) (map[string]string, map[string]string, bool, bool) {
	labels := map[string]string{}
	annotations := map[string]string{}
	labelsMapOwned := false
	annotationsMapOwned := false
	for _, entry := range object.GetManagedFields() {
		if entry.Manager != garageOperatorFieldManager ||
			entry.Operation != metav1.ManagedFieldsOperationApply ||
			entry.Subresource != "" || entry.FieldsV1 == nil {
			continue
		}

		var fields map[string]json.RawMessage
		if err := json.Unmarshal(entry.FieldsV1.GetRawBytes(), &fields); err != nil {
			continue
		}
		metadata, ok := rawObjectField(fields, "f:metadata")
		if !ok {
			continue
		}
		labelsMapOwned = labelsMapOwned || copyOwnedMetadataMap(metadata, "labels", object.GetLabels(), labels)
		annotationsMapOwned = annotationsMapOwned || copyOwnedMetadataMap(metadata, "annotations", object.GetAnnotations(), annotations)
	}
	return labels, annotations, labelsMapOwned, annotationsMapOwned
}

func copyOwnedMetadataMap(
	metadata map[string]json.RawMessage,
	field string,
	current, destination map[string]string,
) bool {
	owned, ok := rawObjectField(metadata, "f:"+field)
	if !ok {
		return false
	}
	mapOwned := false
	for encodedKey := range owned {
		if !strings.HasPrefix(encodedKey, "f:") {
			// "." means the map itself is owned. It is intentionally skipped
			// when copying individual keys during migration.
			mapOwned = true
			continue
		}
		key := strings.TrimPrefix(encodedKey, "f:")
		if value, ok := current[key]; ok {
			destination[key] = value
		}
	}
	return mapOwned
}

func rawObjectField(object map[string]json.RawMessage, field string) (map[string]json.RawMessage, bool) {
	raw, ok := object[field]
	if !ok {
		return nil, false
	}
	var child map[string]json.RawMessage
	if err := json.Unmarshal(raw, &child); err != nil {
		return nil, false
	}
	return child, true
}
