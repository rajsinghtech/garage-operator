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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

const annotationSensitiveGarageConfig = "garage.rajsingh.info/sensitive-garage-config"
const annotationGarageConfigBaseName = "garage.rajsingh.info/garage-config-base-name"

// garageConfigRevision returns the revision that may safely be exposed in
// resource names and workload annotations. A normal config is content-addressed
// with SHA-256. A config containing a Consul ACL token is instead authenticated
// with the pinned RPC identity, so readers of Pods, StatefulSets, or DaemonSets
// do not receive an offline verifier for guesses of a low-entropy token.
func garageConfigRevision(
	ctx context.Context,
	reader client.Reader,
	cluster *garagev1beta2.GarageCluster,
	body string,
) (string, error) {
	if !garageConfigUsesSecret(cluster) {
		return garageConfigHash(body), nil
	}
	rpcSecret, err := GetRPCSecret(ctx, reader, cluster)
	if err != nil {
		return "", fmt.Errorf("deriving sensitive Garage config revision from pinned RPC identity: %w", err)
	}
	mac := hmac.New(sha256.New, rpcSecret)
	_, _ = mac.Write([]byte("garage-operator/garage-config/v1\x00"))
	_, _ = mac.Write([]byte(cluster.Namespace))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(cluster.Name))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func garageConfigAnnotationRevision(
	ctx context.Context,
	reader client.Reader,
	cluster *garagev1beta2.GarageCluster,
	body string,
) (string, error) {
	revision, err := garageConfigRevision(ctx, reader, cluster, body)
	if err != nil {
		return "", err
	}
	return revision[:16], nil
}

func garageConfigRevisionName(baseName, revision string) string {
	if len(revision) > storageConfigRevisionLength {
		revision = revision[:storageConfigRevisionLength]
	}
	if revision == "" {
		sum := garageConfigHash(baseName)
		revision = sum[:storageConfigRevisionLength]
	}
	const maxDNSSubdomainLength = 253
	maxBaseLength := maxDNSSubdomainLength - len(revision) - 1
	if len(baseName) > maxBaseLength {
		baseDigest := garageConfigHash(baseName)[:8]
		maxPrefixLength := maxBaseLength - len(baseDigest) - 1
		baseName = strings.TrimRight(baseName[:maxPrefixLength], "-.") + "-" + baseDigest
	}
	return baseName + "-" + revision
}

func garageConfigRevisionAnnotations(baseName string, managed map[string]string) map[string]string {
	annotations := maps.Clone(managed)
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[annotationGarageConfigBaseName] = baseName
	return annotations
}

func garageNodeConfigBaseName(cluster *garagev1beta2.GarageCluster, node *garagev1beta1.GarageNode) string {
	identity := string(node.UID)
	if identity == "" {
		identity = node.Namespace + "/" + node.Name
	}
	return cluster.Name + "-nodecfg-" + node.Name + "-" + garageConfigHash(identity)[:8]
}

func legacyGarageNodeConfigBaseName(node *garagev1beta1.GarageNode) string {
	return node.Name + "-config"
}

// garageConfigUsesSecret is true exactly when the rendered TOML contains a
// Consul ACL bearer. Upstream Garage v2 has neither a token_file field nor a
// supported environment override for discovery.consul.token, so publishing
// that TOML in a ConfigMap would disclose Secret material to ConfigMap readers.
func garageConfigUsesSecret(cluster *garagev1beta2.GarageCluster) bool {
	return cluster != nil && cluster.Spec.Discovery != nil && cluster.Spec.Discovery.Consul != nil &&
		cluster.Spec.Discovery.Consul.Enabled != nil && *cluster.Spec.Discovery.Consul.Enabled &&
		cluster.Spec.Discovery.Consul.TokenSecretRef != nil
}

func garageConfigVolumeSource(cluster *garagev1beta2.GarageCluster, name string) corev1.VolumeSource {
	if garageConfigUsesSecret(cluster) {
		return corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName:  name,
			DefaultMode: ptr.To[int32](0440),
			Items:       []corev1.KeyToPath{{Key: configFileName, Path: configFileName}},
		}}
	}
	return corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
		LocalObjectReference: corev1.LocalObjectReference{Name: name},
		Items:                []corev1.KeyToPath{{Key: configFileName, Path: configFileName}},
	}}
}

func mountedGarageConfigResource(spec corev1.PodSpec) (name string, secretBacked bool, err error) {
	for i := range spec.Volumes {
		volume := &spec.Volumes[i]
		if volume.Name != configVolumeName {
			continue
		}
		switch {
		case volume.ConfigMap != nil && volume.ConfigMap.Name != "":
			return volume.ConfigMap.Name, false, nil
		case volume.Secret != nil && volume.Secret.SecretName != "":
			return volume.Secret.SecretName, true, nil
		default:
			return "", false, fmt.Errorf("workload template has an invalid %q volume source", configVolumeName)
		}
	}
	return "", false, fmt.Errorf("workload template has no ConfigMap-or-Secret-backed %q volume", configVolumeName)
}

func readGarageConfigResource(
	ctx context.Context,
	reader client.Reader,
	namespace,
	name string,
	secretBacked bool,
) (string, client.Object, error) {
	key := types.NamespacedName{Namespace: namespace, Name: name}
	if secretBacked {
		secret := &corev1.Secret{}
		if err := reader.Get(ctx, key, secret); err != nil {
			return "", nil, err
		}
		body, ok := secret.Data[configFileName]
		if !ok {
			return "", secret, fmt.Errorf("secret %s has no %q entry", key, configFileName)
		}
		return string(body), secret, nil
	}
	configMap := &corev1.ConfigMap{}
	if err := reader.Get(ctx, key, configMap); err != nil {
		return "", nil, err
	}
	body, ok := configMap.Data[configFileName]
	if !ok {
		return "", configMap, fmt.Errorf("ConfigMap %s has no %q entry", key, configFileName)
	}
	return body, configMap, nil
}

func garageConfigResourceIsImmutable(object client.Object) bool {
	switch typed := object.(type) {
	case *corev1.ConfigMap:
		return typed.Immutable != nil && *typed.Immutable
	case *corev1.Secret:
		return typed.Immutable != nil && *typed.Immutable
	default:
		return false
	}
}

type garageConfigResourceReference struct {
	name         string
	secretBacked bool
}

// garageConfigResourcesReferencedByPods returns exact kind/name references.
// ConfigMaps and Secrets can legally coexist at the same name during a safe
// sensitivity transition, so a name-only inventory could retain or delete the
// wrong object.
func garageConfigResourcesReferencedByPods(
	ctx context.Context,
	reader client.Reader,
	namespace string,
) (map[garageConfigResourceReference]struct{}, error) {
	pods := &corev1.PodList{}
	if err := reader.List(ctx, pods, client.InNamespace(namespace)); err != nil {
		return nil, err
	}
	references := make(map[garageConfigResourceReference]struct{})
	for i := range pods.Items {
		for j := range pods.Items[i].Spec.Volumes {
			volume := &pods.Items[i].Spec.Volumes[j]
			if volume.Name != configVolumeName {
				continue
			}
			if volume.ConfigMap != nil && volume.ConfigMap.Name != "" {
				references[garageConfigResourceReference{name: volume.ConfigMap.Name}] = struct{}{}
			}
			if volume.Secret != nil && volume.Secret.SecretName != "" {
				references[garageConfigResourceReference{name: volume.Secret.SecretName, secretBacked: true}] = struct{}{}
			}
		}
	}
	return references, nil
}

// cleanupObsoleteGarageConfigResources removes stale shared, gateway, and
// GarageNode-specific ConfigMap/Secret variants only after no Pod references
// that exact kind/name. This makes adding or removing a Consul ACL token a
// normal serialized rollout instead of deleting a projected volume from
// underneath an old Pod.
func (r *GarageClusterReconciler) cleanupObsoleteGarageConfigResources(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) error {
	references, err := garageConfigResourcesReferencedByPods(ctx, r.nodeLocalPoolReader(), cluster.Namespace)
	if err != nil {
		return fmt.Errorf("listing Pods before Garage config cleanup: %w", err)
	}
	addTemplateReference := func(spec corev1.PodSpec) {
		name, secretBacked, err := mountedGarageConfigResource(spec)
		if err == nil {
			references[garageConfigResourceReference{name: name, secretBacked: secretBacked}] = struct{}{}
		}
	}
	statefulSets := &appsv1.StatefulSetList{}
	if err := r.nodeLocalPoolReader().List(ctx, statefulSets, client.InNamespace(cluster.Namespace), client.MatchingLabels{labelCluster: cluster.Name}); err != nil {
		return fmt.Errorf("listing StatefulSets before Garage config cleanup: %w", err)
	}
	for i := range statefulSets.Items {
		addTemplateReference(statefulSets.Items[i].Spec.Template.Spec)
	}
	daemonSets := &appsv1.DaemonSetList{}
	if err := r.nodeLocalPoolReader().List(ctx, daemonSets, client.InNamespace(cluster.Namespace), client.MatchingLabels{labelCluster: cluster.Name}); err != nil {
		return fmt.Errorf("listing DaemonSets before Garage config cleanup: %w", err)
	}
	for i := range daemonSets.Items {
		addTemplateReference(daemonSets.Items[i].Spec.Template.Spec)
	}
	deployments := &appsv1.DeploymentList{}
	if err := r.nodeLocalPoolReader().List(ctx, deployments, client.InNamespace(cluster.Namespace), client.MatchingLabels{labelCluster: cluster.Name}); err != nil {
		return fmt.Errorf("listing Deployments before Garage config cleanup: %w", err)
	}
	for i := range deployments.Items {
		addTemplateReference(deployments.Items[i].Spec.Template.Spec)
	}

	sharedBaseName := cluster.Name + "-config"
	cfgCtx, err := buildConfigContext(ctx, r.Client, cluster)
	if err != nil {
		return fmt.Errorf("rendering current shared Garage config before revision cleanup: %w", err)
	}
	sharedBody := generateGarageConfig(cluster, cfgCtx)
	sharedRevision, err := garageConfigRevision(ctx, r.nodeLocalPoolReader(), cluster, sharedBody)
	if err != nil {
		return fmt.Errorf("deriving current shared Garage config revision before cleanup: %w", err)
	}
	references[garageConfigResourceReference{
		name:         garageConfigRevisionName(sharedBaseName, sharedRevision),
		secretBacked: garageConfigUsesSecret(cluster),
	}] = struct{}{}

	candidates := make(map[string][]client.Object)
	addCandidate := func(baseName string, owner client.Object) {
		candidates[baseName] = append(candidates[baseName], owner)
	}
	addCandidate(sharedBaseName, cluster)
	addCandidate(cluster.Name+"-gateway-config", cluster)
	nodes := &garagev1beta1.GarageNodeList{}
	if err := r.nodeLocalPoolReader().List(ctx, nodes, client.InNamespace(cluster.Namespace)); err != nil {
		return fmt.Errorf("listing GarageNodes before Garage config cleanup: %w", err)
	}
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if node.Spec.ClusterRef.Name != cluster.Name ||
			(node.Spec.ClusterRef.Namespace != "" && node.Spec.ClusterRef.Namespace != cluster.Namespace) {
			continue
		}
		addCandidate(garageNodeConfigBaseName(cluster, node), node)
		addCandidate(legacyGarageNodeConfigBaseName(node), node)
	}
	cleanup := func(object client.Object, secretBacked bool) error {
		if object.GetLabels()[labelNodeLocalPool] != "" {
			return nil
		}
		baseName := object.GetAnnotations()[annotationGarageConfigBaseName]
		owners, known := candidates[baseName]
		if !known {
			// Fixed-name resources from releases before content addressing carry
			// no revision annotation.
			owners, known = candidates[object.GetName()]
		}
		controlled := false
		for _, owner := range owners {
			if metav1.IsControlledBy(object, owner) {
				controlled = true
				break
			}
		}
		if !known || !controlled {
			return nil
		}
		if _, inUse := references[garageConfigResourceReference{name: object.GetName(), secretBacked: secretBacked}]; inUse {
			return nil
		}
		if err := r.Delete(ctx, object); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting obsolete Garage config resource %s/%s: %w", object.GetNamespace(), object.GetName(), err)
		}
		return nil
	}
	configMaps := &corev1.ConfigMapList{}
	if err := r.nodeLocalPoolReader().List(ctx, configMaps, client.InNamespace(cluster.Namespace)); err != nil {
		return fmt.Errorf("listing ConfigMaps before Garage config cleanup: %w", err)
	}
	for i := range configMaps.Items {
		if err := cleanup(&configMaps.Items[i], false); err != nil {
			return err
		}
	}
	secrets := &corev1.SecretList{}
	if err := r.nodeLocalPoolReader().List(ctx, secrets, client.InNamespace(cluster.Namespace)); err != nil {
		return fmt.Errorf("listing Secrets before Garage config cleanup: %w", err)
	}
	for i := range secrets.Items {
		if err := cleanup(&secrets.Items[i], true); err != nil {
			return err
		}
	}
	return nil
}

func reconcileGarageConfigSecret(
	ctx context.Context,
	c client.Client,
	scheme *runtime.Scheme,
	owner client.Object,
	namespace,
	name,
	body string,
	revision string,
	labels,
	managedAnnotations map[string]string,
	immutable bool,
) (string, error) {
	annotations := maps.Clone(managedAnnotations)
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[annotationSensitiveGarageConfig] = annotationTrue
	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: namespace, Labels: maps.Clone(labels), Annotations: annotations,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{configFileName: []byte(body)},
	}
	if immutable {
		desired.Immutable = ptr.To(true)
	}
	if err := controllerutil.SetControllerReference(owner, desired, scheme); err != nil {
		return "", err
	}
	existing := &corev1.Secret{}
	key := types.NamespacedName{Name: name, Namespace: namespace}
	if err := c.Get(ctx, key, existing); err != nil {
		if errors.IsNotFound(err) {
			return revision, c.Create(ctx, desired)
		}
		return "", err
	}
	if !metav1.IsControlledBy(existing, owner) {
		return "", fmt.Errorf("existing sensitive Garage config Secret %s is not controlled by its exact owner; refusing to read, overwrite, or adopt the collision", key)
	}
	if existing.Immutable != nil && *existing.Immutable && !equality.Semantic.DeepEqual(existing.Data, desired.Data) {
		return "", fmt.Errorf("immutable sensitive Garage config Secret %s does not match its content-addressed name", key)
	}
	metadataChanged := mergeOwnedMetadata(existing, desired)
	if equality.Semantic.DeepEqual(existing.Data, desired.Data) && !metadataChanged &&
		equality.Semantic.DeepEqual(existing.OwnerReferences, desired.OwnerReferences) &&
		equality.Semantic.DeepEqual(existing.Immutable, desired.Immutable) &&
		existing.Type == desired.Type {
		return revision, nil
	}
	existing.Data = desired.Data
	existing.OwnerReferences = desired.OwnerReferences
	existing.Immutable = desired.Immutable
	existing.Type = desired.Type
	return revision, c.Update(ctx, existing)
}

func reconcileGarageConfigMap(
	ctx context.Context,
	c client.Client,
	scheme *runtime.Scheme,
	owner client.Object,
	namespace,
	name,
	body string,
	revision string,
	labels,
	managedAnnotations map[string]string,
	immutable bool,
) (string, error) {
	desired := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: namespace, Labels: maps.Clone(labels), Annotations: maps.Clone(managedAnnotations),
		},
		Data: map[string]string{configFileName: body},
	}
	if immutable {
		desired.Immutable = ptr.To(true)
	}
	if err := controllerutil.SetControllerReference(owner, desired, scheme); err != nil {
		return "", err
	}
	existing := &corev1.ConfigMap{}
	key := types.NamespacedName{Name: name, Namespace: namespace}
	if err := c.Get(ctx, key, existing); err != nil {
		if errors.IsNotFound(err) {
			return revision, c.Create(ctx, desired)
		}
		return "", err
	}
	if !metav1.IsControlledBy(existing, owner) {
		return "", fmt.Errorf("existing Garage config ConfigMap %s is not controlled by its exact owner; refusing to read, overwrite, or adopt the collision", key)
	}
	if existing.Immutable != nil && *existing.Immutable && !equality.Semantic.DeepEqual(existing.Data, desired.Data) {
		return "", fmt.Errorf("immutable Garage config ConfigMap %s does not match its content-addressed name", key)
	}
	metadataChanged := mergeOwnedMetadata(existing, desired)
	if equality.Semantic.DeepEqual(existing.Data, desired.Data) && !metadataChanged &&
		equality.Semantic.DeepEqual(existing.OwnerReferences, desired.OwnerReferences) &&
		equality.Semantic.DeepEqual(existing.Immutable, desired.Immutable) {
		return revision, nil
	}
	existing.Data = desired.Data
	existing.OwnerReferences = desired.OwnerReferences
	existing.Immutable = desired.Immutable
	return revision, c.Update(ctx, existing)
}
