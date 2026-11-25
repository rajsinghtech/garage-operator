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

// Web admin UI (spec.admin.webUI) on the operator's default Garage image
// (>= v2.6.0, which embeds the UI): WebUIAvailable reports the feature, the
// in-cluster URL serves the UI without a token while /v2 still needs one, the
// operator creates and owns the Ingress when --enable-ingress is on, and
// removing spec.admin.webUI removes it. Runs in the "layout" catch-all shard.
var _ = Describe("Web admin UI", Ordered, Label("web-ui"), func() {
	const (
		testNamespace = "garage-web-ui"
		clusterName   = "webui-cluster"
		ingressName   = clusterName + "-webui"
		hostname      = "garage-ui.e2e.example.com"
		adminToken    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		deployment    = "deployment/garage-operator-controller-manager"
	)
	inClusterURL := fmt.Sprintf("http://%s.%s.svc.cluster.local:3903/ui/", clusterName, testNamespace)

	jsonpath := func(g Gomega, kind, name, path string) string {
		out, err := utils.Run(exec.Command("kubectl", "get", kind, name, "-n", testNamespace, "-o", "jsonpath="+path))
		g.Expect(err).NotTo(HaveOccurred(), "get %s/%s: %s", kind, name, out)
		return strings.TrimSpace(out)
	}
	condition := func(g Gomega, condType string) (status, reason string) {
		status = jsonpath(g, "garagecluster", clusterName, fmt.Sprintf(`{.status.conditions[?(@.type=="%s")].status}`, condType))
		reason = jsonpath(g, "garagecluster", clusterName, fmt.Sprintf(`{.status.conditions[?(@.type=="%s")].reason}`, condType))
		return status, reason
	}
	restartOperator := func() {
		out, err := utils.Run(exec.Command("kubectl", "rollout", "status", deployment, "-n", namespace, "--timeout=3m"))
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "rollout: %s", out)
		ExpectWithOffset(1, waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())
		EventuallyWithOffset(1, func(g Gomega) {
			_, err := controllerManagerPodReady(namespace)
			g.Expect(err).NotTo(HaveOccurred(), "Controller not Ready")
		}, 3*time.Minute, 5*time.Second).Should(Succeed())
	}
	// curlInCluster runs one curl in a restricted Pod and returns its output.
	curlInCluster := func(podName string, args ...string) string {
		_, _ = utils.Run(exec.Command("kubectl", "delete", "pod", podName, "-n", testNamespace, "--ignore-not-found", "--timeout=60s"))
		quoted := make([]string, len(args))
		for i, a := range args {
			quoted[i] = fmt.Sprintf("%q", a)
		}
		overrides := fmt.Sprintf(`{"spec":{"containers":[{"name":"curl","image":%q,"imagePullPolicy":"IfNotPresent",
"command":["curl"],"args":[%s],
"securityContext":{"readOnlyRootFilesystem":true,"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},
"runAsNonRoot":true,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"}}}]}}`, e2eCurlImage, strings.Join(quoted, ","))
		out, err := utils.Run(exec.Command("kubectl", "run", podName, "--restart=Never", "-n", testNamespace,
			"--image="+e2eCurlImage, "--overrides", overrides))
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "run %s: %s", podName, out)
		EventuallyWithOffset(1, func(g Gomega) {
			g.Expect(jsonpath(g, "pod", podName, "{.status.phase}")).To(Equal("Succeeded"))
		}, 3*time.Minute, 2*time.Second).Should(Succeed())
		logs, err := utils.Run(exec.Command("kubectl", "logs", podName, "-n", testNamespace))
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "logs %s: %s", podName, logs)
		return logs
	}

	BeforeAll(func() {
		By("enabling Ingress support on the suite controller-manager")
		output, err := utils.Run(exec.Command("kubectl", "set", "env", deployment, "-n", namespace, "ENABLE_INGRESS=true"))
		Expect(err).NotTo(HaveOccurred(), "set env: %s", output)
		restartOperator()

		By("creating test namespace")
		Expect(createE2ETestNamespace(testNamespace)).To(Succeed())
		_, err = utils.Run(exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted"))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		if output, err := utils.Run(exec.Command("kubectl", "delete", "garagecluster", clusterName,
			"-n", testNamespace, "--ignore-not-found", "--wait=false")); err != nil {
			reportE2ECleanupWait("web-ui GarageCluster delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("web-ui GarageCluster", waitForE2EResourceDeleted(
			"garagecluster", clusterName, testNamespace, 3*time.Minute,
		))
		if output, err := utils.Run(exec.Command("kubectl", "delete", "ns", testNamespace,
			"--ignore-not-found", "--wait=false")); err != nil {
			reportE2ECleanupWait("web-ui namespace delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("web-ui namespace", waitForE2ENamespaceDeleted(testNamespace, 2*time.Minute))
		// Later specs in this shard expect the operator's default flags.
		if output, err := utils.Run(exec.Command("kubectl", "set", "env", deployment, "-n", namespace, "ENABLE_INGRESS-")); err != nil {
			reportE2ECleanupWait("web-ui ENABLE_INGRESS reset", fmt.Errorf("%v: %s", err, output))
		} else if output, err := utils.Run(exec.Command("kubectl", "rollout", "status", deployment, "-n", namespace, "--timeout=3m")); err != nil {
			reportE2ECleanupWait("web-ui operator rollout", fmt.Errorf("%v: %s", err, output))
		} else {
			reportE2ECleanupWait("web-ui webhook route", waitForE2EWebhookRoute(namespace, 2*time.Minute))
			_, err := controllerManagerPodReady(namespace)
			reportE2ECleanupWait("web-ui controller ready", err)
		}
		finishE2ECleanupWaits()
	})

	It("reports the UI, serves it in-cluster, and exposes it through an owned Ingress", func() {
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
  admin:
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
    webUI:
      hostname: %[3]s
      ingress:
        ingressClassName: e2e-no-controller
        annotations:
          e2e.garage.rajsingh.info/owner: web-ui
  security:
    allowInsecureSecretPermissions: true
`, clusterName, testNamespace, hostname)

		By("applying the cluster (retry until the webhook is up)")
		Eventually(func(g Gomega) {
			c := exec.Command("kubectl", "apply", "-f", "-")
			c.Stdin = strings.NewReader(clusterYAML)
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred(), "cluster rejected: %s", out)
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("waiting for the cluster to be Running")
		Eventually(func(g Gomega) {
			g.Expect(jsonpath(g, "garagecluster", clusterName, "{.status.phase}")).To(Equal("Running"))
		}, 8*time.Minute, 5*time.Second).Should(Succeed())

		By("checking WebUIAvailable and WebUIExposed")
		Eventually(func(g Gomega) {
			status, reason := condition(g, "WebUIAvailable")
			g.Expect(status).To(Equal("True"), "WebUIAvailable reason %q", reason)
			g.Expect(reason).To(Equal("FeaturePresent"))
			status, reason = condition(g, "WebUIExposed")
			g.Expect(status).To(Equal("True"), "WebUIExposed reason %q", reason)
			g.Expect(reason).To(Equal("Exposed"))
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("checking status.endpoints.webUI")
		Eventually(func(g Gomega) {
			g.Expect(jsonpath(g, "garagecluster", clusterName, "{.status.endpoints.webUI.inCluster}")).To(Equal(inClusterURL))
			g.Expect(jsonpath(g, "garagecluster", clusterName, "{.status.endpoints.webUI.external}")).
				To(Equal("http://" + hostname + "/ui/"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("checking the generated Ingress routes the host root to the admin port")
		Eventually(func(g Gomega) {
			g.Expect(jsonpath(g, "ingress", ingressName, "{.spec.ingressClassName}")).To(Equal("e2e-no-controller"))
			g.Expect(jsonpath(g, "ingress", ingressName, "{.spec.rules[0].host}")).To(Equal(hostname))
			g.Expect(jsonpath(g, "ingress", ingressName, "{.spec.rules[0].http.paths[0].path}")).To(Equal("/"))
			g.Expect(jsonpath(g, "ingress", ingressName, "{.spec.rules[0].http.paths[0].backend.service.name}")).To(Equal(clusterName))
			g.Expect(jsonpath(g, "ingress", ingressName, "{.spec.rules[0].http.paths[0].backend.service.port.name}")).To(Equal("admin"))
			g.Expect(jsonpath(g, "ingress", ingressName, `{.metadata.annotations.e2e\.garage\.rajsingh\.info/owner}`)).To(Equal("web-ui"))
			g.Expect(jsonpath(g, "ingress", ingressName, "{.metadata.ownerReferences[0].kind}")).To(Equal("GarageCluster"))
			g.Expect(jsonpath(g, "ingress", ingressName, "{.metadata.ownerReferences[0].name}")).To(Equal(clusterName))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("fetching the UI from the in-cluster URL without a token")
		body := curlInCluster("webui-curl-ui", "-sS", "--retry", "30", "--retry-all-errors", "--retry-delay", "2", "-f", inClusterURL)
		Expect(body).To(ContainSubstring("/ui/assets/"), "UI index.html: %s", body)

		By("checking the Admin API behind the same port still needs a token")
		code := curlInCluster("webui-curl-api", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
			fmt.Sprintf("http://%s.%s.svc.cluster.local:3903/v2/GetClusterStatus", clusterName, testNamespace))
		Expect(strings.TrimSpace(code)).To(Equal("403"))
	})

	It("removes the Ingress and WebUIExposed when spec.admin.webUI is removed", func() {
		out, err := utils.Run(exec.Command("kubectl", "patch", "garagecluster", clusterName, "-n", testNamespace,
			"--type=json", "-p", `[{"op":"remove","path":"/spec/admin/webUI"}]`))
		Expect(err).NotTo(HaveOccurred(), "patch: %s", out)

		Eventually(func(g Gomega) {
			out, err := utils.Run(exec.Command("kubectl", "get", "ingress", ingressName, "-n", testNamespace, "--ignore-not-found", "-o", "name"))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(BeEmpty(), "Ingress still present")
			status, _ := condition(g, "WebUIExposed")
			g.Expect(status).To(BeEmpty(), "WebUIExposed should be removed")
			g.Expect(jsonpath(g, "garagecluster", clusterName, "{.status.endpoints.webUI.external}")).To(BeEmpty())
			g.Expect(jsonpath(g, "garagecluster", clusterName, "{.status.endpoints.webUI.inCluster}")).To(Equal(inClusterURL))
			// The UI is still served: the operator cannot turn it off.
			status, _ = condition(g, "WebUIAvailable")
			g.Expect(status).To(Equal("True"))
		}, 3*time.Minute, 5*time.Second).Should(Succeed())
	})
})
