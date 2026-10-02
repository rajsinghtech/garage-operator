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
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rajsinghtech/garage-operator/test/utils"
)

// Pod extras (#441): an init container seeds an emptyDir, a sidecar reads it,
// a bad sidecar image stops the rollout at the single identity and a revert
// recovers it, and the webhook rejects a malformed container.
var _ = Describe("Pod extras", Ordered, Label("pod-extras"), func() {
	const (
		testNamespace = "garage-pod-extras"
		clusterName   = "pe-cluster"
		podName       = clusterName + "-storage-0-0"
		adminToken    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		sidecarName   = "reader"
		seedText      = "seeded-by-init"
		badImage      = "example.invalid/does-not-exist:1"
	)

	kubectlJSONPatch := func(patch string) {
		cmd := exec.Command("kubectl", "patch", "garagecluster", clusterName, "-n", testNamespace,
			"--type=json", "-p", patch)
		out, err := utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "patch failed: %s", out)
	}

	expectRunning := func() {
		EventuallyWithOffset(1, func(g Gomega) {
			c := exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace,
				"-o", "jsonpath={.status.phase}")
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal("Running"), "cluster not Running: %s", out)
		}, 8*time.Minute, 5*time.Second).Should(Succeed())
	}

	sidecarImage := func(g Gomega) string {
		c := exec.Command("kubectl", "get", "pod", podName, "-n", testNamespace, "-o",
			fmt.Sprintf(`jsonpath={.spec.containers[?(@.name=="%s")].image}`, sidecarName))
		out, err := utils.Run(c)
		g.Expect(err).NotTo(HaveOccurred())
		return strings.TrimSpace(out)
	}

	BeforeAll(func() {
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
	})

	AfterAll(func() {
		if output, err := utils.Run(exec.Command("kubectl", "delete", "garagecluster", clusterName,
			"-n", testNamespace, "--ignore-not-found", "--wait=false")); err != nil {
			reportE2ECleanupWait("pod-extras GarageCluster delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("pod-extras GarageCluster", waitForE2EResourceDeleted(
			"garagecluster", clusterName, testNamespace, 3*time.Minute,
		))
		if output, err := utils.Run(exec.Command("kubectl", "delete", "ns", testNamespace,
			"--ignore-not-found", "--wait=false")); err != nil {
			reportE2ECleanupWait("pod-extras namespace delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("pod-extras namespace", waitForE2ENamespaceDeleted(testNamespace, 2*time.Minute))
		finishE2ECleanupWaits()
	})

	It("runs an init container and a sidecar that share an extra volume", func() {
		secret := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: garage-admin-token
  namespace: %s
type: Opaque
stringData:
  admin-token: %q
`, testNamespace, adminToken)
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(secret)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		restricted := `securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop: ["ALL"]
          seccompProfile:
            type: RuntimeDefault`
		clusterYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
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
    securityContext:
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
    initContainers:
      - name: seed
        image: %[3]s
        imagePullPolicy: IfNotPresent
        command: ["/bin/sh", "-c", "echo %[5]s > /scratch/seed"]
        volumeMounts:
          - name: scratch
            mountPath: /scratch
        %[6]s
    extraContainers:
      - name: %[4]s
        image: %[3]s
        imagePullPolicy: IfNotPresent
        command: ["/bin/sh", "-c", "while true; do cat /scratch/seed; sleep 5; done"]
        volumeMounts:
          - name: scratch
            mountPath: /scratch
        %[6]s
    extraVolumes:
      - name: scratch
        emptyDir: {}
  admin:
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
  security:
    allowInsecureSecretPermissions: true
`, clusterName, testNamespace, e2eCurlImage, sidecarName, seedText, restricted)

		By("applying the cluster (retry until the webhook is up)")
		Eventually(func(g Gomega) {
			c := exec.Command("kubectl", "apply", "-f", "-")
			c.Stdin = strings.NewReader(clusterYAML)
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred(), "cluster rejected: %s", out)
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("waiting for the cluster to be Running")
		expectRunning()

		By("verifying the sidecar read what the init container wrote")
		Eventually(func(g Gomega) {
			c := exec.Command("kubectl", "logs", podName, "-n", testNamespace, "-c", sidecarName)
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(ContainSubstring(seedText))
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying garage is still the first container")
		c := exec.Command("kubectl", "get", "pod", podName, "-n", testNamespace, "-o",
			"jsonpath={.spec.containers[0].name}")
		out, err := utils.Run(c)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(out)).To(Equal("garage"))

		By("verifying PodExtrasValid is True")
		Eventually(func(g Gomega) {
			c := exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace, "-o",
				`jsonpath={.status.conditions[?(@.type=="PodExtrasValid")].status}`)
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(Equal("True"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	It("rejects a malformed extra container at admission", func() {
		cmd := exec.Command("kubectl", "patch", "garagecluster", clusterName, "-n", testNamespace,
			"--type=json", "-p",
			`[{"op":"add","path":"/spec/storage/extraContainers/-","value":{"name":"typo","image":"x","volumeMount":[]}}]`)
		out, err := utils.Run(cmd)
		Expect(err).To(HaveOccurred())
		Expect(out + fmt.Sprint(err)).To(ContainSubstring("volumeMount"))

		cmd = exec.Command("kubectl", "patch", "garagecluster", clusterName, "-n", testNamespace,
			"--type=json", "-p",
			`[{"op":"add","path":"/spec/storage/extraContainers/-","value":{"name":"x","image":"x","volumeMounts":[{"name":"metadata","mountPath":"/m"}]}}]`)
		out, err = utils.Run(cmd)
		Expect(err).To(HaveOccurred())
		Expect(out + fmt.Sprint(err)).To(ContainSubstring("metadata"))
	})

	It("stops at one identity on a bad sidecar image and recovers on revert", func() {
		By("breaking the sidecar image")
		kubectlJSONPatch(fmt.Sprintf(
			`[{"op":"replace","path":"/spec/storage/extraContainers/0/image","value":%q}]`, badImage))

		By("waiting for the replacement pod to carry the bad image and fail to start it")
		Eventually(func(g Gomega) {
			g.Expect(sidecarImage(g)).To(Equal(badImage))
			c := exec.Command("kubectl", "get", "pod", podName, "-n", testNamespace, "-o", "jsonpath={.status.containerStatuses[*].state.waiting.reason}")
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Or(ContainSubstring("ImagePullBackOff"), ContainSubstring("ErrImagePull")))
		}, 8*time.Minute, 5*time.Second).Should(Succeed())

		By("reverting the image")
		kubectlJSONPatch(fmt.Sprintf(
			`[{"op":"replace","path":"/spec/storage/extraContainers/0/image","value":%q}]`, e2eCurlImage))

		By("waiting for the cluster to recover")
		Eventually(func(g Gomega) {
			g.Expect(sidecarImage(g)).To(Equal(e2eCurlImage))
		}, 8*time.Minute, 5*time.Second).Should(Succeed())
		expectRunning()
	})
})
