/*
Copyright 2026.

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
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

// A Secret referenced only by a user extra container (a sidecar's envFrom or an
// init container's env) must be retained by the static-credentials cleanup. The
// cleanup scans every container of every live pod spec, so no change was needed
// for #441; this pins that behavior.
func TestCleanupStaticCredentialSnapshotsRetainsSecretsUsedOnlyByPodExtras(t *testing.T) {
	ctx := context.Background()
	scheme := managedPVCTestScheme(t)
	controller := true
	clusterUID := types.UID("cluster-uid")
	owner := metav1.OwnerReference{
		APIVersion: garagev1beta2.GroupVersion.String(), Kind: "GarageCluster", Name: "store",
		UID: clusterUID, Controller: &controller,
	}
	labels := map[string]string{labelCluster: "store", labelStaticCredentialsSnapshot: annotationTrue}
	current := "store-credentials-current"
	sidecarOnly := "store-credentials-sidecar-only"
	initOnly := "store-credentials-init-only"
	stsOnly := "store-credentials-sts-only"
	unused := "store-credentials-unused"

	objects := make([]client.Object, 0, 8)
	objects = append(objects, &garagev1beta2.GarageCluster{ObjectMeta: metav1.ObjectMeta{
		Name: "store", Namespace: "default", UID: clusterUID,
		Annotations: map[string]string{annotationStaticCredentialsSecret: current},
	}})
	for _, name := range []string{current, sidecarOnly, initOnly, stsOnly, unused} {
		objects = append(objects, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "default", UID: types.UID(name + "-uid"),
			Labels: labels, OwnerReferences: []metav1.OwnerReference{owner},
		}})
	}
	objects = append(objects, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "store-0", Namespace: "default", Labels: map[string]string{labelCluster: "store"}},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name: "wait-for-vip",
				Env: []corev1.EnvVar{{Name: "TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: initOnly},
				}}}},
			}},
			Containers: []corev1.Container{
				{Name: defaultAppName},
				{Name: "ddns", EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: sidecarOnly},
				}}}},
			},
		},
	})
	objects = append(objects, &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "store-gateway", Namespace: "default", Labels: map[string]string{labelCluster: "store"}},
		Spec: appsv1.StatefulSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: defaultAppName}, {Name: "ddns", EnvFrom: []corev1.EnvFromSource{{
				SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: stsOnly}},
			}}}},
		}}},
	})

	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	r := &GarageClusterReconciler{Client: base, APIReader: base}
	cluster := &garagev1beta2.GarageCluster{}
	if err := base.Get(ctx, types.NamespacedName{Name: "store", Namespace: "default"}, cluster); err != nil {
		t.Fatal(err)
	}
	if err := r.cleanupUnusedStaticCredentialSnapshots(ctx, cluster); err != nil {
		t.Fatal(err)
	}
	for _, retained := range []string{current, sidecarOnly, initOnly, stsOnly} {
		if err := base.Get(ctx, types.NamespacedName{Name: retained, Namespace: "default"}, &corev1.Secret{}); err != nil {
			t.Errorf("Secret %q referenced by a pod extra was deleted: %v", retained, err)
		}
	}
	if err := base.Get(ctx, types.NamespacedName{Name: unused, Namespace: "default"}, &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Fatalf("unused snapshot still exists or lookup failed unexpectedly: %v", err)
	}
}
