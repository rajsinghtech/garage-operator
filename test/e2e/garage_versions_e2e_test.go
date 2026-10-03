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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rajsinghtech/garage-operator/test/utils"
)

const (
	// e2eGarageVersionImageEnv names the Garage image the version-compatibility
	// spec runs. The CI floor lane sets it to the oldest supported release and
	// the nightly canary sets it to a build of Garage's main-v2 branch. The spec
	// skips when it is unset so an unfiltered local run is not affected.
	e2eGarageVersionImageEnv = "E2E_GARAGE_VERSION_IMAGE"
	// e2eGarageVersionExpectEnv optionally names a substring that
	// status.buildInfo.version must contain (for example "2.0.0" on the floor
	// lane), proving the lane really ran the release it claims to.
	e2eGarageVersionExpectEnv = "E2E_GARAGE_VERSION_EXPECT"

	e2eVersionAdminToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// e2eRestrictedClusterTail is the pod-security boilerplate every storage block
// below needs because the test namespaces enforce the restricted profile.
const e2eRestrictedClusterTail = `    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      fsGroup: 1000
      seccompProfile:
        type: RuntimeDefault
    containerSecurityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop:
          - ALL
      seccompProfile:
        type: RuntimeDefault
`

// deployOperatorForVersionSpecs installs CRDs and the operator the same way
// every other self-contained block does, then creates a restricted test
// namespace holding the admin token Secret.
func deployOperatorForVersionSpecs(testNamespace string) {
	GinkgoHelper()
	By("creating manager namespace")
	Expect(ensureE2ENamespaceActive(namespace)).To(Succeed())
	output, err := utils.Run(exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
		"pod-security.kubernetes.io/enforce=restricted"))
	Expect(err).NotTo(HaveOccurred(), "Failed to label manager namespace: %s", output)

	By("installing CRDs")
	_, err = utils.Run(exec.Command("make", "install"))
	Expect(err).NotTo(HaveOccurred())
	Expect(utils.WaitCRDsEstablished()).To(Succeed())

	By("deploying the controller-manager")
	_, err = utils.Run(exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage)))
	Expect(err).NotTo(HaveOccurred())
	Expect(waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())

	By("waiting for controller-manager pod to be Ready")
	Eventually(func(g Gomega) {
		_, err := controllerManagerPodReady(namespace)
		g.Expect(err).NotTo(HaveOccurred(), "Controller not Ready")
	}, 3*time.Minute, 5*time.Second).Should(Succeed())

	By("creating test namespace")
	Expect(createE2ETestNamespace(testNamespace)).To(Succeed())
	_, err = utils.Run(exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
		"pod-security.kubernetes.io/enforce=restricted"))
	Expect(err).NotTo(HaveOccurred())

	secret := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: garage-admin-token
  namespace: %s
type: Opaque
stringData:
  admin-token: %q
`, testNamespace, e2eVersionAdminToken)
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(secret)
	out, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "admin token secret: %s", out)
}

// applyWithWebhookRetry applies manifests, retrying while the admission
// webhook endpoint is still settling.
func applyWithWebhookRetry(manifest string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		c := exec.Command("kubectl", "apply", "-f", "-")
		c.Stdin = strings.NewReader(manifest)
		out, err := utils.Run(c)
		g.Expect(err).NotTo(HaveOccurred(), "apply rejected: %s", out)
	}, 2*time.Minute, 5*time.Second).Should(Succeed())
}

func waitClusterRunning(testNamespace, clusterName string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		c := exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace,
			"-o", "jsonpath={.status.phase}")
		out, err := utils.Run(c)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(Equal("Running"), "cluster not Running: %s", out)
	}, 8*time.Minute, 5*time.Second).Should(Succeed())
}

func teardownVersionSpecs(testNamespace string, clusterName string) {
	if output, err := utils.Run(exec.Command("kubectl", "delete", "garagecluster", clusterName,
		"-n", testNamespace, "--ignore-not-found", "--wait=false")); err != nil {
		reportE2ECleanupWait("version-spec GarageCluster delete request", fmt.Errorf("%v: %s", err, output))
	}
	reportE2ECleanupWait("version-spec GarageCluster", waitForE2EResourceDeleted(
		"garagecluster", clusterName, testNamespace, 3*time.Minute,
	))
	if output, err := utils.Run(exec.Command("kubectl", "delete", "ns", testNamespace,
		"--ignore-not-found", "--wait=false")); err != nil {
		reportE2ECleanupWait("version-spec namespace delete request", fmt.Errorf("%v: %s", err, output))
	}
	reportE2ECleanupWait("version-spec namespace", waitForE2ENamespaceDeleted(testNamespace, 2*time.Minute))
	finishE2ECleanupWaits()
}

// Garage version compatibility (G-02): the core data path on an explicitly
// chosen Garage image. The CI floor lane (oldest supported release) and the
// nightly main-v2 canary run exactly this spec with a different image; the
// rest of the suite already runs the operator's default image.
var _ = Describe("Garage version compatibility", Ordered, Label("garage-versions"), func() {
	const (
		testNamespace = "garage-versions"
		clusterName   = "gv-cluster"
		bucketName    = "gv-bucket"
		keyName       = "gv-key"
		importedKey   = "gv-imported-key"
		// Valid under every Garage grammar: "GK" + 24 hex, 64 hex secret.
		importedID     = "GK0123456789abcdef01234567"
		importedSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	var garageImage string

	BeforeAll(func() {
		garageImage = strings.TrimSpace(os.Getenv(e2eGarageVersionImageEnv))
		if garageImage == "" {
			Skip(fmt.Sprintf("%s is not set; this spec runs in the CI version-matrix lanes", e2eGarageVersionImageEnv))
		}
		By(fmt.Sprintf("running Garage image %s", garageImage))
		deployOperatorForVersionSpecs(testNamespace)
	})

	AfterAll(func() {
		if garageImage == "" {
			return
		}
		teardownVersionSpecs(testNamespace, clusterName)
	})

	It("starts a cluster and serves buckets and keys", func() {
		applyWithWebhookRetry(fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  image: %[3]s
  zone: site-a
  replication:
    factor: 1
  storage:
    replicas: 1
    metadata:
      size: 1Gi
    data:
      size: 1Gi
    resources:
      limits:
        memory: 256Mi
      requests:
        memory: 128Mi
%[4]s  admin:
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
  security:
    allowInsecureSecretPermissions: true
`, clusterName, testNamespace, garageImage, e2eRestrictedClusterTail))

		By("waiting for the cluster to be Running")
		waitClusterRunning(testNamespace, clusterName)

		By("verifying the running Garage version")
		var version string
		Eventually(func(g Gomega) {
			c := exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace,
				"-o", "jsonpath={.status.buildInfo.version}")
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred())
			version = strings.TrimSpace(out)
			g.Expect(version).NotTo(BeEmpty(), "status.buildInfo.version not reported yet")
		}, 3*time.Minute, 5*time.Second).Should(Succeed())
		GinkgoWriter.Printf("Garage reports version %q\n", version)
		if want := strings.TrimSpace(os.Getenv(e2eGarageVersionExpectEnv)); want != "" {
			Expect(version).To(ContainSubstring(want),
				"the lane claims to run Garage %s", want)
		}

		By("creating a bucket, a generated key and an imported key")
		applyWithWebhookRetry(fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: %[1]s
  namespace: %[5]s
spec:
  clusterRef:
    name: %[6]s
---
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: %[2]s
  namespace: %[5]s
spec:
  clusterRef:
    name: %[6]s
  allBuckets:
    read: true
    write: true
---
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: %[3]s
  namespace: %[5]s
spec:
  clusterRef:
    name: %[6]s
  importKey:
    accessKeyId: %[4]s
    secretAccessKey: %[7]s
`, bucketName, keyName, importedKey, importedID, testNamespace, clusterName, importedSecret))

		expectPhaseReady := func(kind, name string) {
			GinkgoHelper()
			Eventually(func(g Gomega) {
				c := exec.Command("kubectl", "get", kind, name, "-n", testNamespace,
					"-o", "jsonpath={.status.phase}")
				out, err := utils.Run(c)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(Equal("Ready"), "%s/%s not ready: phase=%s", kind, name, out)
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
		}
		expectPhaseReady("garagebucket", bucketName)
		expectPhaseReady("garagekey", keyName)
		expectPhaseReady("garagekey", importedKey)

		By("verifying the imported key kept its access key ID")
		c := exec.Command("kubectl", "get", "garagekey", importedKey, "-n", testNamespace,
			"-o", "jsonpath={.status.accessKeyId}")
		out, err := utils.Run(c)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(out)).To(Equal(importedID))
	})
})

// Garage-native kubernetes_discovery (G-07): the one lane that runs Garage
// with spec.discovery.kubernetes enabled, using the namespaced RBAC the docs
// recommend (skipCRD + a pre-installed CRD). Needs Garage >= 2.4.1; v2.3.0 and
// v2.4.0 panic at start with any discovery configured.
var _ = Describe("Garage kubernetes_discovery", Ordered, Label("k8s-discovery"), func() {
	const (
		testNamespace = "garage-k8s-discovery"
		clusterName   = "kd-cluster"
		replicas      = 2
	)

	BeforeAll(func() {
		deployOperatorForVersionSpecs(testNamespace)
	})

	AfterAll(func() {
		teardownVersionSpecs(testNamespace, clusterName)
	})

	It("publishes every node through Garage's GarageNode custom resources", func() {
		By("installing Garage's CRD, ServiceAccount and namespaced RBAC")
		applyWithWebhookRetry(fmt.Sprintf(`
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: garagenodes.deuxfleurs.fr
spec:
  group: deuxfleurs.fr
  names:
    kind: GarageNode
    plural: garagenodes
    singular: garagenode
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          required: [spec]
          properties:
            spec:
              type: object
              required: [address, hostname, port]
              properties:
                address:
                  type: string
                hostname:
                  type: string
                port:
                  type: integer
                  minimum: 0
                  maximum: 65535
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: garage
  namespace: %[1]s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: garage-discovery
  namespace: %[1]s
rules:
  - apiGroups: ["deuxfleurs.fr"]
    resources: ["garagenodes"]
    verbs: ["get", "list", "create", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: garage-discovery
  namespace: %[1]s
subjects:
  - kind: ServiceAccount
    name: garage
    namespace: %[1]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: garage-discovery
`, testNamespace))
		out, err := utils.Run(exec.Command("kubectl", "wait", "--for=condition=Established",
			"crd/garagenodes.deuxfleurs.fr", "--timeout=60s"))
		Expect(err).NotTo(HaveOccurred(), "CRD not established: %s", out)

		By("creating a cluster with kubernetes discovery on the pinned v2.4.1 image")
		applyWithWebhookRetry(fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  image: %[3]s
  serviceAccountName: garage
  zone: site-a
  replication:
    factor: %[4]d
  storage:
    replicas: %[4]d
    metadata:
      size: 1Gi
    data:
      size: 1Gi
    resources:
      limits:
        memory: 256Mi
      requests:
        memory: 128Mi
%[5]s  discovery:
    kubernetes:
      enabled: true
      namespace: %[2]s
      serviceName: %[1]s
      skipCRD: true
  admin:
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
  security:
    allowInsecureSecretPermissions: true
`, clusterName, testNamespace, e2eGarageImage, replicas, e2eRestrictedClusterTail))

		By("waiting for the cluster to be Running")
		waitClusterRunning(testNamespace, clusterName)

		By("verifying Garage itself published one deuxfleurs.fr GarageNode per pod")
		Eventually(func(g Gomega) {
			c := exec.Command("kubectl", "get", "garagenodes.deuxfleurs.fr", "-n", testNamespace,
				"-o", "jsonpath={range .items[*]}{.spec.address}{\"\\n\"}{end}")
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred())
			var addresses []string
			for _, line := range strings.Split(out, "\n") {
				if line = strings.TrimSpace(line); line != "" {
					addresses = append(addresses, line)
				}
			}
			g.Expect(addresses).To(HaveLen(replicas),
				"expected one published GarageNode per pod, got %v", addresses)
		}, 5*time.Minute, 5*time.Second).Should(Succeed())
	})
})
