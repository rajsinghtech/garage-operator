//go:build e2e
// +build e2e

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

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rajsinghtech/garage-operator/test/utils"
)

// COSI tests require additional infrastructure that's not set up in the standard E2E suite:
// 1. The COSI controller must be installed (kubectl apply -k https://github.com/kubernetes-sigs/container-object-storage-interface)
// 2. The operator must be deployed with COSI enabled (--set cosi.enabled=true)
// 3. A GarageCluster must be running and ready
// Skip these tests by default. To run them, set up the full COSI stack first.
var _ = Describe("COSI Driver", Ordered, Label("cosi"), func() {
	const (
		timeout       = 2 * time.Minute
		interval      = 5 * time.Second
		cosiNamespace = "garage-operator-system" // namespace for shadow COSI resources
	)

	BeforeAll(func() {
		// Skip COSI tests unless explicitly enabled via environment variable
		// COSI tests require: COSI controller, operator with COSI enabled, GarageCluster
		if os.Getenv("ENABLE_COSI_TESTS") != "true" {
			Skip("COSI tests disabled. Set ENABLE_COSI_TESTS=true to run them.")
		}

		By("applying COSI CRDs")
		cosiCRDs := []string{
			"bucketclaims",
			"bucketaccesses",
			"bucketclasses",
			"bucketaccessclasses",
			"buckets",
		}
		for _, crd := range cosiCRDs {
			cmd := exec.Command("kubectl", "apply", "-f",
				fmt.Sprintf("https://raw.githubusercontent.com/kubernetes-sigs/container-object-storage-interface/main/client/config/crd/objectstorage.k8s.io_%s.yaml", crd))
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply COSI CRD: %s", crd)
		}

		By("waiting for COSI CRDs to be established")
		for _, crd := range cosiCRDs {
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "crd",
					fmt.Sprintf("%s.objectstorage.k8s.io", crd))
				_, err := utils.Run(cmd)
				return err
			}, timeout, interval).Should(Succeed(), "COSI CRD not established: %s", crd)
		}

		By("creating BucketClass")
		cmd := exec.Command("kubectl", "apply", "-f", "config/samples/cosi/bucketclass.yaml")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create BucketClass")

		By("creating BucketAccessClass")
		cmd = exec.Command("kubectl", "apply", "-f", "config/samples/cosi/bucketaccessclass.yaml")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create BucketAccessClass")
	})

	AfterAll(func() {
		By("cleaning up COSI resources")
		cmd := exec.Command("kubectl", "delete", "-f", "config/samples/cosi/", "--ignore-not-found")
		_, _ = utils.Run(cmd)

		By("cleaning up COSI CRDs")
		cosiCRDs := []string{
			"bucketclaims",
			"bucketaccesses",
			"bucketclasses",
			"bucketaccessclasses",
			"buckets",
		}
		for _, crd := range cosiCRDs {
			cmd := exec.Command("kubectl", "delete", "crd",
				fmt.Sprintf("%s.objectstorage.k8s.io", crd), "--ignore-not-found")
			_, _ = utils.Run(cmd)
		}
	})

	Context("Bucket Provisioning", func() {
		It("should create a bucket via BucketClaim", func() {
			By("creating BucketClaim")
			cmd := exec.Command("kubectl", "apply", "-f", "config/samples/cosi/bucketclaim.yaml")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create BucketClaim")

			By("waiting for BucketClaim to be bound")
			Eventually(func() string {
				cmd := exec.Command("kubectl", "get", "bucketclaim", "my-bucket", "-n", "default",
					"-o", "jsonpath={.status.bucketReady}")
				output, _ := utils.Run(cmd)
				return output
			}, timeout, interval).Should(Equal("true"), "BucketClaim not ready")

			By("verifying shadow GarageBucket exists")
			Eventually(func() string {
				// Query by label since shadow resources use hash-based names
				cmd := exec.Command("kubectl", "get", "garagebucket",
					"-n", cosiNamespace,
					"-l", "garage.rajsingh.info/cosi-managed=true",
					"-o", "jsonpath={.items[*].metadata.name}")
				output, _ := utils.Run(cmd)
				return output
			}, timeout, interval).ShouldNot(BeEmpty(), "Shadow GarageBucket not found")
		})

		It("should create access credentials via BucketAccess", func() {
			By("creating BucketAccess")
			cmd := exec.Command("kubectl", "apply", "-f", "config/samples/cosi/bucketaccess.yaml")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create BucketAccess")

			By("waiting for credentials secret to be created")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "secret", "my-bucket-creds", "-n", "default")
				_, err := utils.Run(cmd)
				return err
			}, timeout, interval).Should(Succeed(), "Credentials secret not found")

			By("verifying secret contains COSI keys")
			cmd = exec.Command("kubectl", "get", "secret", "my-bucket-creds", "-n", "default",
				"-o", "jsonpath={.data}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("accessKeyID"), "Secret missing accessKeyID")

			By("verifying shadow GarageKey exists")
			Eventually(func() string {
				// Query by label since shadow resources use hash-based names
				cmd := exec.Command("kubectl", "get", "garagekey",
					"-n", cosiNamespace,
					"-l", "garage.rajsingh.info/cosi-managed=true",
					"-o", "jsonpath={.items[*].metadata.name}")
				output, _ := utils.Run(cmd)
				return output
			}, timeout, interval).ShouldNot(BeEmpty(), "Shadow GarageKey not found")
		})

		It("should clean up resources on deletion", func() {
			By("deleting BucketAccess")
			cmd := exec.Command("kubectl", "delete", "bucketaccess", "my-bucket-access", "-n", "default")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete BucketAccess")

			By("waiting for credentials secret to be deleted")
			Eventually(func() error {
				cmd := exec.Command("kubectl", "get", "secret", "my-bucket-creds", "-n", "default")
				_, err := utils.Run(cmd)
				return err
			}, timeout, interval).ShouldNot(Succeed(), "Credentials secret should be deleted")

			By("deleting BucketClaim")
			cmd = exec.Command("kubectl", "delete", "bucketclaim", "my-bucket", "-n", "default")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete BucketClaim")

			By("waiting for shadow GarageBucket to be deleted")
			Eventually(func() string {
				// Query by label since shadow resources use hash-based names
				cmd := exec.Command("kubectl", "get", "garagebucket",
					"-n", cosiNamespace,
					"-l", "garage.rajsingh.info/cosi-managed=true",
					"-o", "jsonpath={.items[*].metadata.name}")
				output, _ := utils.Run(cmd)
				return output
			}, timeout, interval).Should(BeEmpty(), "Shadow GarageBucket should be deleted")
		})
	})
})
