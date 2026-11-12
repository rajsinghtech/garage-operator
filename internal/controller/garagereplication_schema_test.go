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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
)

// The GarageReplication API must be correct without the admission webhook
// (which envtest does not run): these cases go through the real API server's
// OpenAPI and CEL validation only.
var _ = Describe("GarageReplication CRD schema", func() {
	var seq int
	replication := func(mutate func(*garagev1beta1.GarageReplication)) *garagev1beta1.GarageReplication {
		seq++
		r := &garagev1beta1.GarageReplication{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("repl-schema-%d", seq), Namespace: "default"},
			Spec: garagev1beta1.GarageReplicationSpec{
				Source: garagev1beta1.ReplicationEndpoint{
					ClusterRef:           &garagev1beta1.ClusterReference{Name: "garage"},
					CredentialsSecretRef: garagev1beta1.ReplicationCredentialsRef{Name: "src"},
				},
				Destination: garagev1beta1.ReplicationEndpoint{
					Endpoint:             &garagev1beta1.ReplicationS3Endpoint{URL: "https://s3.dr.example.com"},
					CredentialsSecretRef: garagev1beta1.ReplicationCredentialsRef{Name: "dst"},
				},
				Buckets: []garagev1beta1.ReplicationBucket{
					{Source: "medias", Destination: "medias"},
					{Source: "pg-backups", Destination: "pg-backups-dr"},
				},
			},
		}
		if mutate != nil {
			mutate(r)
		}
		return r
	}

	It("accepts a valid object and applies defaults", func() {
		r := replication(nil)
		Expect(k8sClient.Create(ctx, r)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, r)).To(Succeed()) })
		Expect(r.Spec.Mode).To(Equal(garagev1beta1.ReplicationModeCopy))
		Expect(r.Spec.Verification).To(Equal(garagev1beta1.ReplicationVerificationNone))
		Expect(r.Spec.Destination.Endpoint.Region).To(Equal(garagev1beta1.ReplicationDefaultRegion))
		Expect(r.Spec.Source.CredentialsSecretRef.AccessKeyIDKey).To(Equal(garagev1beta1.ReplicationDefaultAccessKeyIDKey))
		Expect(r.Spec.Source.CredentialsSecretRef.SecretAccessKeyKey).To(Equal(garagev1beta1.ReplicationDefaultSecretAccessKeyKey))
	})

	It("accepts Mirror with maxDeletes and a CA bundle with the default key", func() {
		r := replication(func(r *garagev1beta1.GarageReplication) {
			r.Spec.Mode = garagev1beta1.ReplicationModeMirror
			r.Spec.Mirror = &garagev1beta1.ReplicationMirrorConfig{MaxDeletes: 100}
			r.Spec.Destination.Endpoint.CABundleRef = &garagev1beta1.ReplicationCABundleRef{Name: "dr-ca"}
		})
		Expect(k8sClient.Create(ctx, r)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, r)).To(Succeed()) })
		Expect(r.Spec.Destination.Endpoint.CABundleRef.Key).To(Equal(garagev1beta1.ReplicationDefaultCABundleKey))
	})

	DescribeTable("rejects",
		func(mutate func(*garagev1beta1.GarageReplication), want string) {
			err := k8sClient.Create(ctx, replication(mutate))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(want))
		},
		Entry("an empty bucket list", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Buckets = nil
		}, "spec.buckets"),
		Entry("a missing destination bucket", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Buckets[0].Destination = ""
		}, "spec.buckets[0].destination"),
		Entry("an invalid source bucket name", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Buckets[0].Source = "Medias;rm"
		}, "spec.buckets[0].source"),
		Entry("an invalid destination bucket name", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Buckets[0].Destination = "-medias"
		}, "spec.buckets[0].destination"),
		Entry("two entries with the same destination", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Buckets[1].Destination = "medias"
		}, "Duplicate value"),
		Entry("both clusterRef and endpoint", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Source.Endpoint = &garagev1beta1.ReplicationS3Endpoint{URL: "https://s3.example.com"}
		}, "exactly one of clusterRef or endpoint must be set"),
		Entry("neither clusterRef nor endpoint", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Source.ClusterRef = nil
		}, "exactly one of clusterRef or endpoint must be set"),
		Entry("a kubeConfigSecretRef", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Source.ClusterRef.KubeConfigSecretRef = &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "kc"}, Key: "config",
			}
		}, "kubeConfigSecretRef is not supported"),
		Entry("credentials in the URL", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Destination.Endpoint.URL = "https://GK1:secret@s3.example.com"
		}, "spec.destination.endpoint.url"),
		Entry("a path in the URL", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Destination.Endpoint.URL = "https://s3.example.com/medias"
		}, "spec.destination.endpoint.url"),
		Entry("a query in the URL", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Destination.Endpoint.URL = "https://s3.example.com?x=1"
		}, "spec.destination.endpoint.url"),
		Entry("a non-http scheme", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Destination.Endpoint.URL = "ftp://s3.example.com"
		}, "spec.destination.endpoint.url"),
		Entry("an invalid Secret name", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Source.CredentialsSecretRef.Name = "Src_Creds"
		}, "spec.source.credentialsSecretRef.name"),
		Entry("an invalid Secret data key", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Source.CredentialsSecretRef.AccessKeyIDKey = "a key"
		}, "spec.source.credentialsSecretRef.accessKeyIdKey"),
		Entry("identical credential keys", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Source.CredentialsSecretRef.AccessKeyIDKey = "k"
			r.Spec.Source.CredentialsSecretRef.SecretAccessKeyKey = "k"
		}, "accessKeyIdKey and secretAccessKeyKey must be different"),
		Entry("a secret access key stored under the default ID key", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Source.CredentialsSecretRef.SecretAccessKeyKey = garagev1beta1.ReplicationDefaultAccessKeyIDKey
		}, "accessKeyIdKey and secretAccessKeyKey must be different"),
		Entry("an invalid CA ConfigMap name", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Destination.Endpoint.CABundleRef = &garagev1beta1.ReplicationCABundleRef{Name: "CA Bundle"}
		}, "spec.destination.endpoint.caBundleRef.name"),
		Entry("mode Mirror without mirror", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Mode = garagev1beta1.ReplicationModeMirror
		}, "mirror must be set if and only if mode is Mirror"),
		Entry("mirror with mode Copy", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Mirror = &garagev1beta1.ReplicationMirrorConfig{MaxDeletes: 1}
		}, "mirror must be set if and only if mode is Mirror"),
		Entry("mirror.maxDeletes 0", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Mode = garagev1beta1.ReplicationModeMirror
			r.Spec.Mirror = &garagev1beta1.ReplicationMirrorConfig{}
		}, "spec.mirror.maxDeletes"),
		Entry("the removed Archive mode", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Mode = "Archive"
		}, "spec.mode"),
		Entry("a bucket replicated onto itself on the same endpoint", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Source.ClusterRef = nil
			r.Spec.Source.Endpoint = &garagev1beta1.ReplicationS3Endpoint{URL: "https://S3.dr.example.com"}
		}, "a bucket cannot be replicated onto itself"),
		Entry("an invalid bandwidth limit", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Transfer = &garagev1beta1.ReplicationTransferConfig{BandwidthLimit: "10M --delete-before"}
		}, "spec.transfer.bandwidthLimit"),
		Entry("a too long schedule", func(r *garagev1beta1.GarageReplication) {
			r.Spec.Schedule = fmt.Sprintf("%0129d", 0)
		}, "spec.schedule"),
	)
})
