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
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rajsinghtech/garage-operator/test/utils"
)

var (
	// Optional Environment Variables:
	// - CERT_MANAGER_INSTALL_SKIP=true: Skips CertManager installation during test setup.
	// These variables are useful if CertManager is already installed, avoiding
	// re-installation and conflicts.
	skipCertManagerInstall = os.Getenv("CERT_MANAGER_INSTALL_SKIP") == "true"
	// isCertManagerAlreadyInstalled will be set true when CertManager CRDs be found on the cluster
	isCertManagerAlreadyInstalled = false

	// projectImage is the name of the image which will be build and loaded
	// with the code source changes to be tested.
	projectImage = "example.com/garage-operator:v0.0.1"
)

// TestE2E runs the end-to-end (e2e) test suite for the project. These tests execute in an isolated,
// temporary environment to validate project changes with the purpose of being used in CI jobs.
// The default setup requires Kind, builds/loads the Manager Docker image locally, and installs
// CertManager.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting garage-operator integration test suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	// E2E_SKIP_SUITE_SETUP=true is set by test scripts that handle cluster/operator setup
	// themselves (e.g., hack/e2e-external-gateway.sh) and just want to run specific Ginkgo specs.
	if os.Getenv("E2E_SKIP_SUITE_SETUP") == "true" {
		return
	}

	// E2E_SKIP_IMAGE_BUILD=true reuses an image already present in the local
	// image store under projectImage (CI builds it once and shares it across
	// shards); it is still loaded into this shard's Kind cluster below.
	var err error
	if os.Getenv("E2E_SKIP_IMAGE_BUILD") == "true" {
		By("reusing the prebuilt manager(Operator) image")
		cmd := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", projectImage)
		_, err = utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(),
			"E2E_SKIP_IMAGE_BUILD=true but the prebuilt manager(Operator) image is missing")
	} else {
		By("building the manager(Operator) image")
		cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build the manager(Operator) image")
	}

	// TODO(user): If you want to change the e2e test vendor from Kind, ensure the image is
	// built and available before running the tests. Also, remove the following block.
	By("loading the manager(Operator) image on Kind")
	err = utils.LoadImageToKindClusterWithName(projectImage)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to load the manager(Operator) image into Kind")

	// The tests-e2e are intended to run on a temporary cluster that is created and destroyed for testing.
	// To prevent errors when tests run in environments with CertManager already installed,
	// we check for its presence before execution.
	// Setup CertManager before the suite if not skipped and if not already installed
	if !skipCertManagerInstall {
		By("checking if cert manager is installed already")
		isCertManagerAlreadyInstalled = utils.IsCertManagerCRDsInstalled()
		if !isCertManagerAlreadyInstalled {
			_, _ = fmt.Fprintf(GinkgoWriter, "Installing CertManager...\n")
			Expect(utils.InstallCertManager()).To(Succeed(), "Failed to install CertManager")
		} else {
			_, _ = fmt.Fprintf(GinkgoWriter, "WARNING: CertManager is already installed. Skipping installation...\n")
		}
	}
})

// captureFailureDiagnostics writes operator logs and cluster state for a failed
// spec while the cluster is still intact.
//
// This runs as JustAfterEach, the earliest cleanup hook Ginkgo offers: it fires
// immediately after the subject node, before any DeferCleanup registered inside
// the spec and before a Describe-level AfterAll runs "make undeploy". Both of
// those destroy the evidence — an AfterEach here still ran after a spec's own
// DeferCleanup had deleted the namespace, and CI's post-run collection step
// observes a fully torn-down cluster and uploads an empty artifact.
var _ = JustAfterEach(func() {
	report := CurrentSpecReport()
	if !report.Failed() {
		return
	}
	directory := os.Getenv("E2E_DEBUG_DIR")
	if directory == "" {
		directory = "/tmp/e2e-debug"
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "WARNING: cannot create %s: %v\n", directory, err)
		return
	}
	slug := failureArtifactSlug(report.FullText())
	for name, args := range map[string][]string{
		"operator-logs": {
			"logs", "deployment/garage-operator-controller-manager",
			"-n", "garage-operator-system", "--tail=2000",
		},
		// A crashed-and-restarted operator is the case where the current
		// container's log is least useful: it starts after the interesting part.
		// Fails harmlessly (and is recorded as such) when there was no restart.
		"operator-logs-previous": {
			"logs", "deployment/garage-operator-controller-manager",
			"-n", "garage-operator-system", "--previous", "--tail=2000",
		},
		"garage-resources": {
			"get", "garageclusters,garagenodes,garagebuckets,garagekeys",
			"-A", "-o", "yaml",
		},
		"workloads": {"get", "all,pvc,pv", "-A"},
		"events":    {"get", "events", "-A", "--sort-by=.lastTimestamp"},
	} {
		output, err := utils.Run(exec.Command("kubectl", args...))
		if err != nil {
			output += "\n" + err.Error()
		}
		path := filepath.Join(directory, slug+"-"+name+".txt")
		if writeErr := os.WriteFile(path, []byte(output), 0o600); writeErr != nil {
			_, _ = fmt.Fprintf(GinkgoWriter, "WARNING: cannot write %s: %v\n", path, writeErr)
			continue
		}
		_, _ = fmt.Fprintf(GinkgoWriter, "wrote failure diagnostics to %s\n", path)
	}
})

// failureArtifactSlug reduces a spec name to a bounded, filesystem-safe stem.
func failureArtifactSlug(name string) string {
	var builder strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r + ('a' - 'A'))
		default:
			builder.WriteByte('-')
		}
	}
	slug := strings.Trim(builder.String(), "-")
	for strings.Contains(slug, "--") {
		slug = strings.ReplaceAll(slug, "--", "-")
	}
	if len(slug) > 80 {
		slug = slug[:80]
	}
	if slug == "" {
		slug = "spec"
	}
	return slug
}

var _ = AfterSuite(func() {
	if os.Getenv("E2E_SKIP_SUITE_SETUP") == "true" {
		return
	}
	// Teardown CertManager after the suite if not skipped and if it was not already installed
	if !skipCertManagerInstall && !isCertManagerAlreadyInstalled {
		_, _ = fmt.Fprintf(GinkgoWriter, "Uninstalling CertManager...\n")
		utils.UninstallCertManager()
	}
})
