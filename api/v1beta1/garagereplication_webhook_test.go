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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func validReplication() *GarageReplication {
	return &GarageReplication{
		ObjectMeta: metav1.ObjectMeta{Name: "repl", Namespace: testSourceNS},
		Spec: GarageReplicationSpec{
			Source: ReplicationEndpoint{
				ClusterRef:           &ClusterReference{Name: testCluster},
				CredentialsSecretRef: ReplicationCredentialsRef{Name: "src"},
			},
			Destination: ReplicationEndpoint{
				Endpoint:             &ReplicationS3Endpoint{URL: "https://s3.dr.example.com"},
				CredentialsSecretRef: ReplicationCredentialsRef{Name: "dst"},
			},
			Buckets: []ReplicationBucket{
				{Source: "medias", Destination: "medias"},
				{Source: "pg-dumps", Destination: "pg-dumps-dr"},
			},
			Schedule: "*/15 * * * *",
		},
	}
}

// Formats, enums, list keys and the mode/mirror pairing are schema rules,
// covered against a real API server in
// internal/controller/garagereplication_schema_test.go. These cases cover
// what only the webhook and the controller check.
func TestValidateGarageReplicationSpec(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*GarageReplication)
		wantErr string
		warning string
	}{
		{name: "valid copy", mutate: func(*GarageReplication) {}},
		{name: "descriptor schedule", mutate: func(r *GarageReplication) { r.Spec.Schedule = "@hourly" }},
		{name: "timezone schedule", mutate: func(r *GarageReplication) { r.Spec.Schedule = "CRON_TZ=Europe/Paris 0 2 * * *" }},
		{name: "one-shot without schedule", mutate: func(r *GarageReplication) { r.Spec.Schedule = "" }},
		{name: "bad schedule", mutate: func(r *GarageReplication) { r.Spec.Schedule = "every 5 minutes" }, wantErr: "not a valid cron expression"},
		{name: "both clusterRef and endpoint", mutate: func(r *GarageReplication) {
			r.Spec.Source.Endpoint = &ReplicationS3Endpoint{URL: "https://x.example.com"}
		}, wantErr: "exactly one of clusterRef or endpoint"},
		{name: "kubeConfigSecretRef", mutate: func(r *GarageReplication) {
			r.Spec.Source.ClusterRef.KubeConfigSecretRef = &corev1.SecretKeySelector{}
		}, wantErr: "kubeConfigSecretRef is not supported"},
		{name: "self loop on the same clusterRef", mutate: func(r *GarageReplication) {
			r.Spec.Destination.Endpoint = nil
			r.Spec.Destination.ClusterRef = &ClusterReference{Name: testCluster}
		}, wantErr: "onto itself"},
		{name: "self loop with an implicit namespace", mutate: func(r *GarageReplication) {
			r.Spec.Destination.Endpoint = nil
			r.Spec.Destination.ClusterRef = &ClusterReference{Name: testCluster, Namespace: testSourceNS}
		}, wantErr: "onto itself"},
		{name: "self loop with another URL spelling", mutate: func(r *GarageReplication) {
			r.Spec.Source.ClusterRef = nil
			r.Spec.Source.Endpoint = &ReplicationS3Endpoint{URL: "HTTPS://s3.dr.example.com:443/"}
		}, wantErr: "onto itself"},
		{name: "same cluster with renamed buckets warns", mutate: func(r *GarageReplication) {
			r.Spec.Destination.Endpoint = nil
			r.Spec.Destination.ClusterRef = &ClusterReference{Name: testCluster}
			r.Spec.Buckets = []ReplicationBucket{{Source: "medias", Destination: "medias-copy"}}
		}, warning: "same cluster"},
		{name: "mirror warns about deletions and the first trigger", mutate: func(r *GarageReplication) {
			r.Spec.Mode = ReplicationModeMirror
			r.Spec.Mirror = &ReplicationMirrorConfig{MaxDeletes: 100}
		}, warning: "first run waits for the garage.rajsingh.info/trigger-sync annotation"},
		{name: "bad pod label", mutate: func(r *GarageReplication) {
			r.Spec.PodTemplate = &ReplicationPodTemplate{Labels: map[string]string{"bad key": "v"}}
		}, wantErr: "podTemplate.labels"},
		{name: "bad pod annotation", mutate: func(r *GarageReplication) {
			r.Spec.PodTemplate = &ReplicationPodTemplate{Annotations: map[string]string{"bad key": "v"}}
		}, wantErr: "podTemplate.annotations"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validReplication()
			tc.mutate(r)
			warnings, err := ValidateGarageReplicationSpec(r)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.warning != "" && !strings.Contains(strings.Join(warnings, "\n"), tc.warning) {
				t.Fatalf("want warning containing %q, got %v", tc.warning, warnings)
			}
		})
	}
}

func TestNormalizeReplicationURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://s3.example.com":     "https://s3.example.com",
		"HTTPS://S3.Example.com/":    "https://s3.example.com",
		"https://s3.example.com:443": "https://s3.example.com",
		"http://garage.ns.svc:80/":   "http://garage.ns.svc",
		"http://garage.ns.svc:3900":  "http://garage.ns.svc:3900",
		"https://s3.example.com:80":  "https://s3.example.com:80",
		"http://[fd00::1]:3900":      "http://[fd00::1]:3900",
		"http://[FD00::1]/":          "http://[fd00::1]",
	} {
		if got := NormalizeReplicationURL(in); got != want {
			t.Errorf("NormalizeReplicationURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFindReplicationDestinationConflict(t *testing.T) {
	older := validReplication()
	older.Name = "older"
	older.CreationTimestamp = metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	newer := validReplication()
	newer.Name = "newer"
	newer.CreationTimestamp = metav1.NewTime(older.CreationTimestamp.Add(time.Hour))

	if other, bucket := FindReplicationDestinationConflict(newer, []GarageReplication{*older, *newer}); other == nil || other.Name != "older" || bucket != "medias" {
		t.Fatalf("newer must lose medias to older, got %v %q", other, bucket)
	}
	if other, _ := FindReplicationDestinationConflict(older, []GarageReplication{*older, *newer}); other != nil {
		t.Fatalf("older keeps its destinations, got conflict with %s", other.Name)
	}

	// An object being created has no creation time and loses to existing ones.
	created := validReplication()
	created.Name = "created"
	if other, _ := FindReplicationDestinationConflict(created, []GarageReplication{*newer}); other == nil {
		t.Fatal("a new object must not take a destination bucket already written")
	}

	// Same bucket names on another destination cluster do not conflict.
	elsewhere := validReplication()
	elsewhere.Name = "elsewhere"
	elsewhere.Spec.Destination.Endpoint.URL = "https://s3.other.example.com"
	if other, _ := FindReplicationDestinationConflict(elsewhere, []GarageReplication{*older}); other != nil {
		t.Fatalf("another destination cluster must not conflict, got %s", other.Name)
	}

	// Another URL spelling of the same destination does conflict.
	spelled := validReplication()
	spelled.Name = "spelled"
	spelled.Spec.Destination.Endpoint.URL = "https://S3.dr.example.com:443/"
	spelled.Spec.Buckets = []ReplicationBucket{{Source: "other", Destination: "pg-dumps-dr"}}
	if other, bucket := FindReplicationDestinationConflict(spelled, []GarageReplication{*older}); other == nil || bucket != "pg-dumps-dr" {
		t.Fatalf("same destination with another spelling must conflict, got %v %q", other, bucket)
	}

	// Disjoint buckets on the same destination are fine.
	disjoint := validReplication()
	disjoint.Name = "disjoint"
	disjoint.Spec.Buckets = []ReplicationBucket{{Source: "logs", Destination: "logs"}}
	if other, _ := FindReplicationDestinationConflict(disjoint, []GarageReplication{*older}); other != nil {
		t.Fatalf("disjoint buckets must not conflict, got %s", other.Name)
	}

	// A clusterRef destination: an omitted namespace equals the object's own.
	byRef := validReplication()
	byRef.Name = "by-ref"
	byRef.CreationTimestamp = older.CreationTimestamp
	byRef.Spec.Destination = ReplicationEndpoint{ClusterRef: &ClusterReference{Name: "dr"}, CredentialsSecretRef: ReplicationCredentialsRef{Name: "dst"}}
	byRefExplicit := byRef.DeepCopy()
	byRefExplicit.Name = "by-ref-explicit"
	byRefExplicit.CreationTimestamp = newer.CreationTimestamp
	byRefExplicit.Spec.Destination.ClusterRef.Namespace = testSourceNS
	if other, _ := FindReplicationDestinationConflict(byRefExplicit, []GarageReplication{*byRef}); other == nil {
		t.Fatal("an implicit and an explicit namespace of one cluster must conflict")
	}
}

func TestGarageReplicationWebhookRejectsTakenDestination(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	existing := validReplication()
	existing.Name = "existing"
	existing.Namespace = testTargetNS
	existing.CreationTimestamp = metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()
	v := &GarageReplicationValidator{Client: c}

	r := validReplication()
	if _, err := v.ValidateCreate(context.Background(), r); err == nil || !strings.Contains(err.Error(), "already written by GarageReplication "+testTargetNS+"/existing") {
		t.Fatalf("want a destination conflict error, got %v", err)
	}
	r.Spec.Buckets = []ReplicationBucket{{Source: "logs", Destination: "logs"}}
	if _, err := v.ValidateCreate(context.Background(), r); err != nil {
		t.Fatalf("a free destination bucket was rejected: %v", err)
	}
}

func TestGarageReplicationWebhookRequiresGrantForCrossNamespaceCluster(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	r := validReplication()
	r.Spec.Source.ClusterRef.Namespace = testTargetNS

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	v := &GarageReplicationValidator{Client: c}
	if _, err := v.ValidateCreate(context.Background(), r); err == nil || !strings.Contains(err.Error(), "GarageReferenceGrant") {
		t.Fatalf("want a missing-grant error, got %v", err)
	}

	grant := &GarageReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow", Namespace: testTargetNS},
		Spec: GarageReferenceGrantSpec{
			From: []ReferenceGrantFrom{{Kind: garageReplicationKind, Namespace: testSourceNS}},
			To:   []ReferenceGrantTo{{Kind: garageClusterKind, Name: testCluster}},
		},
	}
	c = fake.NewClientBuilder().WithScheme(scheme).WithObjects(grant).Build()
	v = &GarageReplicationValidator{Client: c}
	if _, err := v.ValidateCreate(context.Background(), r); err != nil {
		t.Fatalf("granted reference rejected: %v", err)
	}

	// A grant for another kind does not authorize replication.
	grant.Spec.From[0].Kind = garageBucketKind
	c = fake.NewClientBuilder().WithScheme(scheme).WithObjects(grant).Build()
	v = &GarageReplicationValidator{Client: c}
	if _, err := v.ValidateCreate(context.Background(), r); err == nil {
		t.Fatal("a GarageBucket grant must not authorize a GarageReplication")
	}
}
