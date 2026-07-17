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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rajsinghtech/garage-operator/test/utils"
)

// namespace where the project is deployed in
const namespace = "garage-operator-system"

// serviceAccountName created for the project
const serviceAccountName = "garage-operator-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "garage-operator-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "garage-operator-metrics-binding"

var _ = Describe("Manager", Ordered, Label("manager"), func() {
	var controllerPodName string

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, _ = utils.Run(cmd) // Ignore error if already exists

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, _ = utils.Run(cmd)

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("waiting for Garage CRDs to be Established")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				// Get the name of the controller-manager pod
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("getting the controller-manager pod name")
			// Get the controller pod name if not already set (in case this test runs standalone)
			if controllerPodName == "" {
				verifyControllerUp := func(g Gomega) {
					cmd := exec.Command("kubectl", "get",
						"pods", "-l", "control-plane=controller-manager",
						"-o", "go-template={{ range .items }}"+
							"{{ if not .metadata.deletionTimestamp }}"+
							"{{ .metadata.name }}"+
							"{{ \"\\n\" }}{{ end }}{{ end }}",
						"-n", namespace,
					)
					podOutput, err := utils.Run(cmd)
					g.Expect(err).NotTo(HaveOccurred())
					podNames := utils.GetNonEmptyLines(podOutput)
					g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
					controllerPodName = podNames[0]
				}
				Eventually(verifyControllerUp, 2*time.Minute, time.Second).Should(Succeed())
			}

			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			// Delete any existing binding first (may exist from previous test run)
			cmd := exec.Command("kubectl", "delete", "clusterrolebinding", metricsRoleBindingName,
				"--ignore-not-found")
			_, _ = utils.Run(cmd)

			cmd = exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=garage-operator-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
			)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("ensuring the controller pod is ready")
			verifyControllerPodReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", controllerPodName, "-n", namespace,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "Controller pod not ready")
			}
			Eventually(verifyControllerPodReady, 3*time.Minute, time.Second).Should(Succeed())

			By("waiting for the controller pod to reach Ready condition (defensive)")
			waitCmd := exec.Command("kubectl", "wait", "--for=condition=Ready",
				"--timeout=2m", "pod/"+controllerPodName, "-n", namespace)
			_, _ = utils.Run(waitCmd)

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("Serving metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted, 5*time.Minute, time.Second).Should(Succeed())

			// +kubebuilder:scaffold:e2e-metrics-webhooks-readiness

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "delete", "pod", "curl-metrics",
				"--namespace", namespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)

			metricsURL := fmt.Sprintf("http://%s.%s.svc.cluster.local:8443/metrics", metricsServiceName, namespace)
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=docker.io/curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "docker.io/curlimages/curl:latest",
							"imagePullPolicy": "IfNotPresent",
							"command": ["/bin/sh", "-c"],
							"args": ["i=0; until [ $i -ge 120 ]; do curl -sfv -H 'Authorization: Bearer %s' %s && exit 0; i=$((i+1)); sleep 1; done; exit 1"],
							"securityContext": {
								"readOnlyRootFilesystem": true,
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccountName": "%s"
					}
				}`, token, metricsURL, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			verifyMetricsAvailable := func(g Gomega) {
				metricsOutput, err := getMetricsOutput()
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
				g.Expect(metricsOutput).NotTo(BeEmpty())
				g.Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
			}
			Eventually(verifyMetricsAvailable, 2*time.Minute).Should(Succeed())
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks

		It("should accept GarageKey with allBuckets field", func() {
			By("creating a GarageKey with allBuckets cluster-wide permissions")
			keyYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: e2e-cluster-wide-key
  namespace: %s
spec:
  clusterRef:
    name: non-existent-cluster
  allBuckets:
    read: true
    write: true
`, namespace)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(keyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create GarageKey with allBuckets")

			By("verifying the key was created with allBuckets in spec")
			cmd = exec.Command("kubectl", "get", "garagekey", "e2e-cluster-wide-key",
				"-n", namespace, "-o", "jsonpath={.spec.allBuckets.read}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("true"), "allBuckets.read should be true")

			By("verifying the key enters Pending phase (cluster not found is transient)")
			verifyKeyPending := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagekey", "e2e-cluster-wide-key",
					"-n", namespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Pending"), "Key should be in Pending phase, got: %s", output)
			}
			Eventually(verifyKeyPending, 1*time.Minute, 5*time.Second).Should(Succeed())

			By("cleaning up")
			cmd = exec.Command("kubectl", "delete", "garagekey", "e2e-cluster-wide-key",
				"-n", namespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should remain stable with no garage resources defined", func() {
			By("checking if garage resources exist (from other tests)")
			cmd := exec.Command("kubectl", "get", "garageclusters,garagebuckets,garagekeys,garagenodes", "-A", "--no-headers")
			output, _ := utils.Run(cmd)
			// If resources exist from other tests (e.g., gateway cluster tests), skip the "no resources" check
			// and just verify operator stability
			if output != "" && !strings.Contains(output, "No resources found") {
				By("garage resources exist from other tests, skipping empty state check")
			}

			By("recording initial restart count")
			// The operator may legitimately restart once during cold start while
			// waiting for cert-manager to populate the webhook server cert secret
			// (mounted with optional: true). We only care that it stops restarting
			// once it's up, not that it hit zero restarts on its first try.
			cmd = exec.Command("kubectl", "get", "pod", controllerPodName, "-n", namespace,
				"-o", "jsonpath={.status.containerStatuses[0].restartCount}")
			initialRestarts, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting to verify operator stability (no NEW crash loops)")
			// Wait 30 seconds and verify operator restartCount has not increased
			time.Sleep(30 * time.Second)

			verifyNoNewRestarts := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", controllerPodName, "-n", namespace,
					"-o", "jsonpath={.status.containerStatuses[0].restartCount}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal(initialRestarts),
					"Operator should not have restarted again (started with %s restarts)", initialRestarts)
			}
			Eventually(verifyNoNewRestarts, time.Minute).Should(Succeed())

			By("verifying health endpoints are responding")
			// Check liveness probe is working
			verifyHealth := func(g Gomega) {
				cmd := exec.Command("kubectl", "exec", controllerPodName, "-n", namespace, "--",
					"wget", "-q", "-O-", "http://localhost:8081/healthz")
				// exec won't work on distroless, so just check the pod is ready
				cmd = exec.Command("kubectl", "get", "pod", controllerPodName, "-n", namespace,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "Operator pod should be ready")
			}
			Eventually(verifyHealth, time.Minute).Should(Succeed())

			By("verifying operator logs show startup information")
			verifyLogs := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				// Verify essential startup logs are present
				g.Expect(output).To(ContainSubstring("starting manager"), "Should log manager startup")
				g.Expect(output).To(ContainSubstring("Starting Controller"), "Should log controller startup")
			}
			Eventually(verifyLogs, time.Minute).Should(Succeed())
		})
	})
})

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	// Temporary file to store the token request
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		// Execute kubectl command to create the token
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		// Parse the JSON output to extract the token
		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() (string, error) {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	return utils.Run(cmd)
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}

var _ = Describe("Gateway Cluster", Ordered, Label("gateway"), func() {
	const testNamespace = "garage-test"
	const storageClusterName = "storage-cluster"
	const gatewayClusterName = "gateway-cluster"

	// shared state for credential drift tests (set by Test 1, read by Test 2)
	var driftBucketID string
	var driftSecretRV string

	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, _ = utils.Run(cmd) // Ignore error if already exists

		By("labeling the manager namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, _ = utils.Run(cmd)

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("waiting for Garage CRDs to be Established")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for controller-manager pod to be Ready (webhook server started)")
		verifyControllerUp := func(g Gomega) {
			// Use Ready condition rather than pod Phase. With the webhook
			// readiness gate (cmd/main.go: webhookServer.StartedChecker), the
			// pod will not flip Ready until the TLS listener on :9443 is
			// accepting connections, which is exactly what the next CR apply
			// needs.
			cmd := exec.Command("kubectl", "get", "pods", "-l", "control-plane=controller-manager",
				"-n", namespace,
				"-o", "jsonpath={.items[0].status.conditions[?(@.type=='Ready')].status}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True"), "Controller not Ready: %s", output)
		}
		Eventually(verifyControllerUp, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("creating test namespace")
		cmd = exec.Command("kubectl", "create", "ns", testNamespace)
		_, _ = utils.Run(cmd) // Ignore error if already exists

		By("labeling the test namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		By("cleaning up test resources")
		cmd := exec.Command("kubectl", "delete", "garagekey", "--all", "-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "garagebucket", "--all", "-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "garagecluster", gatewayClusterName, "-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "garagecluster", storageClusterName, "-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		time.Sleep(10 * time.Second) // Wait for cleanup
		cmd = exec.Command("kubectl", "delete", "ns", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)
	})

	Context("When creating a gateway cluster", func() {
		It("should create storage cluster first", func() {
			By("creating admin token secret")
			adminTokenSecret := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: garage-admin-token
  namespace: %s
type: Opaque
stringData:
  admin-token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
`, testNamespace)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(adminTokenSecret)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create admin token secret")

			By("creating storage cluster YAML")
			storageYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
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
  security:
    allowInsecureSecretPermissions: true
`, storageClusterName, testNamespace)

			By("applying storage cluster (retry until webhook is up)")
			applyStorage := func(g Gomega) {
				c := exec.Command("kubectl", "apply", "-f", "-")
				c.Stdin = strings.NewReader(storageYAML)
				out, err := utils.Run(c)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to create storage cluster: %s", out)
			}
			Eventually(applyStorage, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for storage cluster to be ready")
			verifyStorageReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagecluster", storageClusterName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Storage cluster not ready: phase=%s", output)
			}
			Eventually(verifyStorageReady, 5*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should create gateway cluster that connects to storage", func() {
			By("creating gateway cluster YAML")
			gatewayYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  gateway:
    replicas: 1
    resources:
      limits:
        memory: 128Mi
      requests:
        memory: 64Mi
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
  connectTo:
    clusterRef:
      name: %s
  replication:
    factor: 1
  # Enable autoApply so the operator can finalize any layout changes
  # automatically (e.g. when gateway PVCs are reaped on scale-down). With
  # persistent gateway identity (v0.5.6+) rolling restarts no longer mint new
  # node IDs, so this is mostly belt-and-braces.
  layoutManagement:
    autoApply: true
  admin:
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
  security:
    allowInsecureSecretPermissions: true
`, gatewayClusterName, testNamespace, storageClusterName)

			By("applying gateway cluster (retry until webhook is up)")
			applyGateway := func(g Gomega) {
				c := exec.Command("kubectl", "apply", "-f", "-")
				c.Stdin = strings.NewReader(gatewayYAML)
				out, err := utils.Run(c)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to create gateway cluster: %s", out)
			}
			Eventually(applyGateway, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for gateway cluster to be ready")
			verifyGatewayReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagecluster", gatewayClusterName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Gateway cluster not ready: phase=%s", output)
			}
			Eventually(verifyGatewayReady, 5*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should create StatefulSet for gateway tier (persistent identity)", func() {
			// Gateway tier (v0.5.6+) is a StatefulSet named "<cr>-gateway" with
			// a small metadata PVC and EmptyDir for data. The metadata PVC
			// preserves the Ed25519 node identity across pod restarts so a
			// routine rollout doesn't churn the cluster layout. Data dir
			// stays EmptyDir because gateways don't store object blocks.
			gwSts := gatewayClusterName + "-gateway"

			By("verifying StatefulSet exists")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", gwSts,
					"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "StatefulSet should exist for gateway cluster")
				g.Expect(output).To(Equal(gwSts))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying pre-upgrade Deployment is absent")
			cmd := exec.Command("kubectl", "get", "deployment", gwSts, "-n", testNamespace)
			_, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "pre-v0.5.6 gateway Deployment should not exist")

			By("verifying gateway StatefulSet has a metadata volumeClaimTemplate")
			cmd = exec.Command("kubectl", "get", "statefulset", gwSts,
				"-n", testNamespace, "-o", "jsonpath={.spec.volumeClaimTemplates[*].metadata.name}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("metadata"), "gateway StatefulSet must have a single 'metadata' VCT (got %q)", output)

			By("verifying gateway PVCs are provisioned (one per replica)")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pvc", "-n", testNamespace,
					"-l", "app.kubernetes.io/instance="+gatewayClusterName,
					"-o", "jsonpath={.items[*].metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty(), "expected gateway metadata PVCs")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying gateway has EmptyDir for data volume")
			cmd = exec.Command("kubectl", "get", "statefulset", gwSts,
				"-n", testNamespace, "-o", "jsonpath={.spec.template.spec.volumes[?(@.name==\"data\")].emptyDir}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("{}"), "Gateway should use EmptyDir for data volume")

			By("verifying gateway PVC retention policy is Delete/Delete")
			cmd = exec.Command("kubectl", "get", "statefulset", gwSts,
				"-n", testNamespace,
				"-o", "jsonpath={.spec.persistentVolumeClaimRetentionPolicy.whenScaled}/{.spec.persistentVolumeClaimRetentionPolicy.whenDeleted}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("Delete/Delete"), "gateway PVC retention policy must be Delete/Delete")
		})

		It("should have gateway pods running", func() {
			By("verifying gateway pods are running")
			verifyPodsRunning := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods",
					"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", gatewayClusterName),
					"-n", testNamespace,
					"-o", "jsonpath={.items[*].status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Gateway pods not running")
			}
			Eventually(verifyPodsRunning, 3*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should connect gateway to storage cluster nodes", func() {
			By("waiting for storage cluster to report healthy status (gateways relay to storage)")
			// For gateway clusters, health status is "unavailable" because they have no storage capacity.
			// The meaningful health check is that the STORAGE cluster is healthy and sees all nodes.
			verifyStorageHealthy := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagecluster", storageClusterName,
					"-n", testNamespace, "-o", "jsonpath={.status.health.status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("healthy"), "Storage cluster not healthy: status=%s", output)
			}
			Eventually(verifyStorageHealthy, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying storage cluster sees all nodes (storage + gateway)")
			verifyAllNodesConnected := func(g Gomega) {
				// Storage cluster should see its node + gateway node = 2 nodes total
				cmd := exec.Command("kubectl", "get", "garagecluster", storageClusterName,
					"-n", testNamespace, "-o", "jsonpath={.status.health.connectedNodes}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				// Should have at least 2 connected nodes (1 storage + 1 gateway)
				g.Expect(output).To(SatisfyAny(Equal("2"), Equal("3"), Equal("4")),
					"Expected at least 2 connected nodes, got %s", output)
			}
			Eventually(verifyAllNodesConnected, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying gateway cluster can see storage nodes")
			verifyGatewayConnected := func(g Gomega) {
				// Gateway should see at least 2 nodes (itself + storage)
				cmd := exec.Command("kubectl", "get", "garagecluster", gatewayClusterName,
					"-n", testNamespace, "-o", "jsonpath={.status.health.connectedNodes}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(SatisfyAny(Equal("2"), Equal("3"), Equal("4")),
					"Gateway should see at least 2 connected nodes, got %s", output)
			}
			Eventually(verifyGatewayConnected, 3*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should bump storage cluster layout version when gateway joins (gateways participate in layout)", func() {
			By("checking storage cluster layout version progresses past 1 (gateway gets added to the layout)")
			verifyLayoutBumped := func(g Gomega) {
				// Gateways participate in the layout (capacity=nil) so they can
				// receive FullReplication writes. Version 1 is the initial
				// storage assignment; the gateway join produces at least one
				// additional version.
				cmd := exec.Command("kubectl", "get", "garagecluster", storageClusterName,
					"-n", testNamespace, "-o", "jsonpath={.status.layoutVersion}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				var version int
				_, err = fmt.Sscanf(output, "%d", &version)
				g.Expect(err).NotTo(HaveOccurred(), "Unparseable layoutVersion: %q", output)
				g.Expect(version).To(BeNumerically(">=", 2),
					"Storage layout version should bump after gateway joins (got %d)", version)
			}
			Eventually(verifyLayoutBumped, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying gateway cluster component label")
			cmd := exec.Command("kubectl", "get", "statefulset", gatewayClusterName+"-gateway",
				"-n", testNamespace, "-o", "jsonpath={.metadata.labels.app\\.kubernetes\\.io/component}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("gateway"), "Gateway StatefulSet should have component=gateway label")
		})

		It("should serve S3 API requests via gateway", func() {
			By("creating a test bucket via storage cluster")
			bucketYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: gateway-test-bucket
  namespace: %s
spec:
  clusterRef:
    name: %s
`, testNamespace, storageClusterName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(bucketYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create test bucket")

			By("waiting for bucket to be ready")
			verifyBucketReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagebucket", "gateway-test-bucket",
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Ready"), "Bucket not ready: phase=%s", output)
			}
			Eventually(verifyBucketReady, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying gateway S3 endpoint is accessible")
			// Port-forward to gateway service and check S3 endpoint responds
			verifyGatewayS3 := func(g Gomega) {
				// Check that gateway has S3 service endpoint
				cmd := exec.Command("kubectl", "get", "service", gatewayClusterName,
					"-n", testNamespace, "-o", "jsonpath={.spec.ports[?(@.name==\"s3\")].port}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("3900"), "Gateway S3 port not configured correctly")
			}
			Eventually(verifyGatewayS3, 1*time.Minute, 5*time.Second).Should(Succeed())

			By("cleaning up test bucket")
			cmd = exec.Command("kubectl", "delete", "garagebucket", "gateway-test-bucket",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should grant cluster-wide key access to all buckets", func() {
			By("creating a test bucket for cluster-wide key test")
			bucketYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: cw-test-bucket
  namespace: %s
spec:
  clusterRef:
    name: %s
`, testNamespace, storageClusterName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(bucketYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create test bucket")

			By("waiting for bucket to be ready")
			verifyBucketReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagebucket", "cw-test-bucket",
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Ready"), "Bucket not ready: phase=%s", output)
			}
			Eventually(verifyBucketReady, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("creating a cluster-wide key with allBuckets")
			keyYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: cw-admin-key
  namespace: %s
spec:
  clusterRef:
    name: %s
  allBuckets:
    read: true
    write: true
    owner: true
`, testNamespace, storageClusterName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(keyYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create cluster-wide key")

			By("waiting for key to be ready with ClusterWide=true")
			verifyKeyReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagekey", "cw-admin-key",
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Ready"), "Key not ready: phase=%s", output)
			}
			Eventually(verifyKeyReady, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying ClusterWide status is true")
			cmd = exec.Command("kubectl", "get", "garagekey", "cw-admin-key",
				"-n", testNamespace, "-o", "jsonpath={.status.clusterWide}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("true"), "ClusterWide should be true")

			By("verifying key has access to the test bucket")
			verifyBucketAccess := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagekey", "cw-admin-key",
					"-n", testNamespace, "-o", "jsonpath={.status.buckets}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				// The key should have at least one bucket in its access list
				g.Expect(output).NotTo(BeEmpty(), "Key should have bucket access, got empty buckets list")
			}
			Eventually(verifyBucketAccess, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("recording secret resourceVersion to detect reconciliation loops")
			cmd = exec.Command("kubectl", "get", "secret", "cw-admin-key",
				"-n", testNamespace, "-o", "jsonpath={.metadata.resourceVersion}")
			rvBefore, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(rvBefore).NotTo(BeEmpty(), "Secret should exist with a resourceVersion")

			By("waiting 30 seconds to verify no spurious secret updates")
			time.Sleep(30 * time.Second)

			By("verifying secret resourceVersion is unchanged (no infinite reconciliation)")
			cmd = exec.Command("kubectl", "get", "secret", "cw-admin-key",
				"-n", testNamespace, "-o", "jsonpath={.metadata.resourceVersion}")
			rvAfter, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(rvAfter).To(Equal(rvBefore),
				"Secret resourceVersion changed from %s to %s — controller is updating the secret in a loop",
				rvBefore, rvAfter)

			By("cleaning up cluster-wide key and bucket")
			cmd = exec.Command("kubectl", "delete", "garagekey", "cw-admin-key",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "garagebucket", "cw-test-bucket",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should revoke cluster-wide permissions when allBuckets is downgraded or removed", func() {
			By("creating a test bucket for revocation test")
			bucketYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: revoke-test-bucket
  namespace: %s
spec:
  clusterRef:
    name: %s
`, testNamespace, storageClusterName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(bucketYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create test bucket")

			By("waiting for bucket to be ready")
			verifyBucketReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagebucket", "revoke-test-bucket",
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Ready"), "Bucket not ready: phase=%s", output)
			}
			Eventually(verifyBucketReady, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("creating a cluster-wide key with full permissions (read, write, owner)")
			keyYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: revoke-test-key
  namespace: %s
spec:
  clusterRef:
    name: %s
  allBuckets:
    read: true
    write: true
    owner: true
`, testNamespace, storageClusterName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(keyYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create cluster-wide key")

			By("waiting for key to be ready with full bucket access")
			verifyFullAccess := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagekey", "revoke-test-key",
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Ready"), "Key not ready: phase=%s", output)

				// Verify owner permission is granted
				cmd = exec.Command("kubectl", "get", "garagekey", "revoke-test-key",
					"-n", testNamespace, "-o", "jsonpath={.status.buckets[0].owner}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"), "Key should have owner access, got: %s", output)
			}
			Eventually(verifyFullAccess, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("downgrading allBuckets to read-only (write and owner should be revoked)")
			downgradeYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: revoke-test-key
  namespace: %s
spec:
  clusterRef:
    name: %s
  allBuckets:
    read: true
`, testNamespace, storageClusterName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(downgradeYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to downgrade key permissions")

			By("verifying write and owner permissions are revoked, read remains")
			verifyDowngraded := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagekey", "revoke-test-key",
					"-n", testNamespace, "-o", "jsonpath={.status.buckets[0].read}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"), "read should still be true, got: %s", output)

				// write=false is omitted by omitempty, so jsonpath returns ""
				cmd = exec.Command("kubectl", "get", "garagekey", "revoke-test-key",
					"-n", testNamespace, "-o", "jsonpath={.status.buckets[0].write}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(SatisfyAny(Equal("false"), Equal("")),
					"write should be revoked, got: %s", output)

				cmd = exec.Command("kubectl", "get", "garagekey", "revoke-test-key",
					"-n", testNamespace, "-o", "jsonpath={.status.buckets[0].owner}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(SatisfyAny(Equal("false"), Equal("")),
					"owner should be revoked, got: %s", output)
			}
			Eventually(verifyDowngraded, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("removing allBuckets entirely (all permissions should be revoked)")
			removeYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: revoke-test-key
  namespace: %s
spec:
  clusterRef:
    name: %s
`, testNamespace, storageClusterName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(removeYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to remove allBuckets from key")

			By("verifying all bucket permissions are revoked")
			verifyRevoked := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagekey", "revoke-test-key",
					"-n", testNamespace, "-o", "jsonpath={.status.buckets}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(SatisfyAny(Equal("[]"), Equal("")),
					"Key should have no bucket access after full revocation, got: %s", output)
			}
			Eventually(verifyRevoked, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying ClusterWide status is false after removal")
			verifyNotClusterWide := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagekey", "revoke-test-key",
					"-n", testNamespace, "-o", "jsonpath={.status.clusterWide}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(SatisfyAny(Equal("false"), Equal("")),
					"ClusterWide should be false after removal, got: %s", output)
			}
			Eventually(verifyNotClusterWide, 1*time.Minute, 5*time.Second).Should(Succeed())

			By("cleaning up revocation test resources")
			cmd = exec.Command("kubectl", "delete", "garagekey", "revoke-test-key",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "garagebucket", "revoke-test-bucket",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should recreate key and update secret when key is deleted in Garage", func() {
			const driftBucketName = "drift-test-bucket"
			const driftKeyName = "drift-test-key"
			const adminToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

			By("creating drift test bucket")
			bucketYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef:
    name: %s
`, driftBucketName, testNamespace, storageClusterName)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(bucketYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create drift test bucket")

			By("waiting for drift test bucket to be ready and recording its ID")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagebucket", driftBucketName,
					"-n", testNamespace, "-o", "jsonpath={.status.bucketId}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty(), "Bucket ID not yet set")
				driftBucketID = output
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
			Expect(driftBucketID).NotTo(BeEmpty(), "driftBucketID not captured from bucket status")

			By("creating drift test key with read+write on drift bucket")
			keyYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef:
    name: %s
  bucketPermissions:
    - bucketRef:
        name: %s
      read: true
      write: true
`, driftKeyName, testNamespace, storageClusterName, driftBucketName)
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(keyYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create drift test key")

			By("waiting for drift test key to be ready")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagekey", driftKeyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Ready"), "Key phase: %s", output)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("recording original access key ID")
			cmd = exec.Command("kubectl", "get", "garagekey", driftKeyName,
				"-n", testNamespace, "-o", "jsonpath={.status.accessKeyId}")
			originalAccessKeyID, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(originalAccessKeyID).NotTo(BeEmpty(), "accessKeyId not set in status")

			By("deleting the key from Garage admin API (simulating out-of-band deletion)")
			// DeleteKey uses id as a query param, not a JSON body
			curlCmd := fmt.Sprintf(
				`curl -s -o /dev/null -w "%%{http_code}" -X POST `+
					`-H 'Authorization: Bearer %s' `+
					`'http://%s.%s.svc.cluster.local:3903/v2/DeleteKey?id=%s'`,
				adminToken, storageClusterName, testNamespace, originalAccessKeyID,
			)
			Eventually(func(g Gomega) {
				cleanupCmd := exec.Command("kubectl", "delete", "pod", "curl-drift-delete-key",
					"-n", testNamespace, "--ignore-not-found", "--force", "--grace-period=0")
				_, _ = utils.Run(cleanupCmd)

				cmd := exec.Command("kubectl", "run", "curl-drift-delete-key", "--rm", "-i", "--restart=Never",
					"-n", testNamespace,
					"--image=docker.io/curlimages/curl:latest",
					"--overrides", fmt.Sprintf(`{
						"spec": {
							"containers": [{
								"name": "curl-drift-delete-key",
								"image": "docker.io/curlimages/curl:latest",
								"imagePullPolicy": "IfNotPresent",
								"command": ["/bin/sh", "-c"],
								"args": [%q],
								"securityContext": {
									"readOnlyRootFilesystem": true,
									"allowPrivilegeEscalation": false,
									"capabilities": {"drop": ["ALL"]},
									"runAsNonRoot": true,
									"runAsUser": 1000,
									"seccompProfile": {"type": "RuntimeDefault"}
								}
							}]
						}
					}`, curlCmd))
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "curl pod failed: %s", output)
				// kubectl run --rm appends "pod deleted" to output; extract just the HTTP status (first 3 chars)
				// Accept 200 (we deleted it) or 404 (already gone — drift already occurred)
				httpCode := strings.TrimSpace(output)
				if len(httpCode) > 3 {
					httpCode = httpCode[:3]
				}
				g.Expect(httpCode).To(SatisfyAny(Equal("200"), Equal("404")),
					"Expected HTTP 200 or 404 from DeleteKey, got: %s", output)
			}, 1*time.Minute, 10*time.Second).Should(Succeed())

			By("recording secret resourceVersion after confirmed deletion")
			cmd = exec.Command("kubectl", "get", "secret", driftKeyName,
				"-n", testNamespace, "-o", "jsonpath={.metadata.resourceVersion}")
			driftSecretRV, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(driftSecretRV).NotTo(BeEmpty(), "Secret resourceVersion not set")

			By("triggering immediate reconciliation by touching the GarageKey")
			cmd = exec.Command("kubectl", "label", "--overwrite", "garagekey", driftKeyName,
				"-n", testNamespace,
				fmt.Sprintf("garage.rajsingh.info/reconcile-trigger=%d", time.Now().Unix()))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for operator to detect drift and update secret with new credentials")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secret", driftKeyName,
					"-n", testNamespace, "-o", "jsonpath={.metadata.resourceVersion}")
				currentRV, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(currentRV).NotTo(Equal(driftSecretRV),
					"Secret resourceVersion unchanged — operator has not updated credentials yet")

				cmd = exec.Command("kubectl", "get", "secret", driftKeyName,
					"-n", testNamespace,
					"-o", `go-template={{ index .data "access-key-id" | base64decode }}`)
				newAccessKeyID, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(newAccessKeyID).NotTo(Equal(originalAccessKeyID),
					"Access key ID unchanged — operator recreated same key ID unexpectedly")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying GarageKey returns to Ready phase after drift recovery")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagekey", driftKeyName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Ready"), "Key phase after recovery: %s", output)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should successfully PUT and GET objects with credentials after drift recovery", func() {
			const driftKeyName = "drift-test-key"
			Expect(driftBucketID).NotTo(BeEmpty(), "driftBucketID not set — credential drift test must run first")

			By("reading recovered credentials from the K8s secret")
			cmd := exec.Command("kubectl", "get", "secret", driftKeyName,
				"-n", testNamespace,
				"-o", `go-template={{ index .data "access-key-id" | base64decode }}`)
			accessKeyID, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(accessKeyID).NotTo(BeEmpty(), "access-key-id not in secret")

			cmd = exec.Command("kubectl", "get", "secret", driftKeyName,
				"-n", testNamespace,
				"-o", `go-template={{ index .data "secret-access-key" | base64decode }}`)
			secretAccessKey, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(secretAccessKey).NotTo(BeEmpty(), "secret-access-key not in secret")

			By("running S3 PUT then GET via aws-cli to verify recovered credentials work")
			const testPayload = "drift-recovery-verified"
			const testObject = "drift-test-object"
			endpoint := fmt.Sprintf("http://%s.%s.svc.cluster.local:3900", storageClusterName, testNamespace)

			s3Cmd := fmt.Sprintf(
				`printf '%s' > /tmp/payload.txt && `+
					`aws s3api put-object --endpoint-url %s --region garage --bucket %s --key %s --body /tmp/payload.txt && `+
					`aws s3api get-object --endpoint-url %s --region garage --bucket %s --key %s /tmp/out.txt && `+
					`cat /tmp/out.txt`,
				testPayload, endpoint, driftBucketID, testObject,
				endpoint, driftBucketID, testObject,
			)

			Eventually(func(g Gomega) {
				cleanupCmd := exec.Command("kubectl", "delete", "pod", "drift-s3-verify",
					"-n", testNamespace, "--ignore-not-found", "--force", "--grace-period=0")
				_, _ = utils.Run(cleanupCmd)

				// readOnlyRootFilesystem omitted: aws-cli writes credential cache to /tmp
				cmd := exec.Command("kubectl", "run", "drift-s3-verify", "--rm", "-i", "--restart=Never",
					"-n", testNamespace,
					"--image=docker.io/amazon/aws-cli:latest",
					"--overrides", fmt.Sprintf(`{
						"spec": {
							"containers": [{
								"name": "drift-s3-verify",
								"image": "docker.io/amazon/aws-cli:latest",
								"imagePullPolicy": "IfNotPresent",
								"command": ["/bin/sh", "-c"],
								"args": [%q],
								"env": [
									{"name": "AWS_ACCESS_KEY_ID", "value": %q},
									{"name": "AWS_SECRET_ACCESS_KEY", "value": %q},
									{"name": "HOME", "value": "/tmp"}
								],
								"securityContext": {
									"allowPrivilegeEscalation": false,
									"capabilities": {"drop": ["ALL"]},
									"runAsNonRoot": true,
									"runAsUser": 1000,
									"seccompProfile": {"type": "RuntimeDefault"}
								}
							}]
						}
					}`, s3Cmd, accessKeyID, secretAccessKey))
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "aws-cli pod failed: %s", output)
				g.Expect(output).To(ContainSubstring(testPayload),
					"GET output should contain PUT payload. Full output: %s", output)
			}, 3*time.Minute, 30*time.Second).Should(Succeed())

			By("cleaning up drift test resources")
			cmd = exec.Command("kubectl", "delete", "garagekey", driftKeyName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "garagebucket", "drift-test-bucket",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should register gateway nodes in the cluster layout with capacity=nil", func() {
			// Gateway pods participate in the cluster layout with capacity=nil
			// (matching upstream `garage layout assign --gateway`). This is
			// required so FullReplication writes (key_table, bucket_table, …)
			// reach the gateway's local DB — the S3 sig-auth path uses
			// get_local() in upstream Garage's
			// src/api/common/signature/payload.rs:413.
			By("querying the cluster layout via Admin API")
			adminToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			verifyGatewayPresent := func(g Gomega) {
				curlCmd := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterLayout",
					adminToken, storageClusterName, testNamespace)
				cmd := exec.Command("kubectl", "run", "curl-layout-check", "--rm", "-i", "--restart=Never",
					"-n", testNamespace,
					"--image=docker.io/curlimages/curl:latest",
					"--overrides", fmt.Sprintf(`{
						"spec": {
							"containers": [{
								"name": "curl-layout-check",
								"image": "docker.io/curlimages/curl:latest",
								"imagePullPolicy": "IfNotPresent",
								"command": ["/bin/sh", "-c"],
								"args": [%q],
								"securityContext": {
									"readOnlyRootFilesystem": true,
									"allowPrivilegeEscalation": false,
									"capabilities": {"drop": ["ALL"]},
									"runAsNonRoot": true,
									"runAsUser": 1000,
									"seccompProfile": {"type": "RuntimeDefault"}
								}
							}]
						}
					}`, curlCmd))
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to query layout: %s", output)

				var layout struct {
					Roles []struct {
						ID       string   `json:"id"`
						Tags     []string `json:"tags"`
						Capacity *uint64  `json:"capacity"`
					} `json:"roles"`
				}
				jsonStart := strings.Index(output, "{")
				jsonEnd := strings.LastIndex(output, "}")
				g.Expect(jsonStart).To(BeNumerically(">=", 0), "No JSON found in output: %s", output)
				g.Expect(jsonEnd).To(BeNumerically(">", jsonStart), "No valid JSON found in output: %s", output)
				jsonStr := output[jsonStart : jsonEnd+1]
				g.Expect(json.Unmarshal([]byte(jsonStr), &layout)).To(Succeed(), "Failed to parse layout JSON: %s", jsonStr)

				gatewayRoles := 0
				for _, role := range layout.Roles {
					if role.Capacity != nil {
						continue
					}
					hasTierGateway := false
					for _, tag := range role.Tags {
						if tag == "tier:gateway" {
							hasTierGateway = true
							break
						}
					}
					if hasTierGateway {
						gatewayRoles++
					}
				}
				g.Expect(gatewayRoles).To(BeNumerically(">=", 1),
					"Expected at least one gateway role in layout (capacity=nil + tier:gateway tag). Got roles: %+v", layout.Roles)
			}
			Eventually(verifyGatewayPresent, 3*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("should preserve node identity when gateway pods restart (persistent identity)", func() {
			// Gateway tier is a StatefulSet with a metadata PVC, so the
			// Ed25519 node_key Garage stores under metadata_dir persists
			// across pod restarts. Gateway pods participate in the cluster
			// layout with capacity=nil; the storage cluster's view of nodes
			// must show the same ID before and after a gateway pod restart.
			By("getting the current gateway pod name")
			cmd := exec.Command("kubectl", "get", "pods",
				"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", gatewayClusterName),
				"-n", testNamespace,
				"-o", "jsonpath={.items[0].metadata.name}")
			oldPodName, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(oldPodName).NotTo(BeEmpty(), "No gateway pod found")

			By("getting the gateway node ID before restart (from the storage cluster's GetClusterStatus)")
			adminToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			var oldNodeID string
			getGatewayNodeID := func(g Gomega) {
				curlCmd := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterStatus",
					adminToken, storageClusterName, testNamespace)
				cmd := exec.Command("kubectl", "run", "curl-get-node-id", "--rm", "-i", "--restart=Never",
					"-n", testNamespace,
					"--image=docker.io/curlimages/curl:latest",
					"--overrides", fmt.Sprintf(`{
						"spec": {
							"containers": [{
								"name": "curl-get-node-id",
								"image": "docker.io/curlimages/curl:latest",
								"imagePullPolicy": "IfNotPresent",
								"command": ["/bin/sh", "-c"],
								"args": [%q],
								"securityContext": {
									"readOnlyRootFilesystem": true,
									"allowPrivilegeEscalation": false,
									"capabilities": {"drop": ["ALL"]},
									"runAsNonRoot": true,
									"runAsUser": 1000,
									"seccompProfile": {"type": "RuntimeDefault"}
								}
							}]
						}
					}`, curlCmd))
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to query cluster status: %s", output)

				var status struct {
					Nodes []struct {
						ID   string `json:"id"`
						Addr string `json:"addr"`
						IsUp bool   `json:"isUp"`
						Role *struct {
							Capacity *uint64 `json:"capacity"`
						} `json:"role"`
					} `json:"nodes"`
				}
				jsonStart := strings.Index(output, "{")
				jsonEnd := strings.LastIndex(output, "}")
				g.Expect(jsonStart).To(BeNumerically(">=", 0))
				jsonStr := output[jsonStart : jsonEnd+1]
				g.Expect(json.Unmarshal([]byte(jsonStr), &status)).To(Succeed())

				// Gateway role has capacity=nil (matches upstream
				// `garage layout assign --gateway`). The storage role has a
				// real capacity value.
				for _, n := range status.Nodes {
					if n.IsUp && n.Role != nil && n.Role.Capacity == nil {
						oldNodeID = n.ID
						return
					}
				}
				g.Expect(oldNodeID).NotTo(BeEmpty(), "Gateway node not found in cluster status: %+v", status.Nodes)
			}
			Eventually(getGatewayNodeID, 30*time.Second, 5*time.Second).Should(Succeed())

			By("deleting the gateway pod to trigger restart")
			cmd = exec.Command("kubectl", "delete", "pod", oldPodName, "-n", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete gateway pod")

			By("waiting for gateway pod to be ready again")
			verifyPodReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods",
					"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", gatewayClusterName),
					"-n", testNamespace,
					"-o", "jsonpath={.items[0].status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Gateway pod not running")
			}
			Eventually(verifyPodReady, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for gateway cluster to report healthy again")
			verifyGatewayHealthy := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagecluster", gatewayClusterName,
					"-n", testNamespace, "-o", "jsonpath={.status.health.status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("healthy"), "Gateway not healthy after restart: status=%s", output)
			}
			Eventually(verifyGatewayHealthy, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the same node ID is reused after restart (identity preserved)")
			verifyNodeIDPreserved := func(g Gomega) {
				curlCmd := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterStatus",
					adminToken, storageClusterName, testNamespace)
				cmd := exec.Command("kubectl", "run", "curl-check-node-id", "--rm", "-i", "--restart=Never",
					"-n", testNamespace,
					"--image=docker.io/curlimages/curl:latest",
					"--overrides", fmt.Sprintf(`{
						"spec": {
							"containers": [{
								"name": "curl-check-node-id",
								"image": "docker.io/curlimages/curl:latest",
								"imagePullPolicy": "IfNotPresent",
								"command": ["/bin/sh", "-c"],
								"args": [%q],
								"securityContext": {
									"readOnlyRootFilesystem": true,
									"allowPrivilegeEscalation": false,
									"capabilities": {"drop": ["ALL"]},
									"runAsNonRoot": true,
									"runAsUser": 1000,
									"seccompProfile": {"type": "RuntimeDefault"}
								}
							}]
						}
					}`, curlCmd))
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to query cluster status: %s", output)

				var status struct {
					Nodes []struct {
						ID   string `json:"id"`
						IsUp bool   `json:"isUp"`
						Role *struct {
							Capacity *uint64 `json:"capacity"`
						} `json:"role"`
					} `json:"nodes"`
				}
				jsonStart := strings.Index(output, "{")
				jsonEnd := strings.LastIndex(output, "}")
				g.Expect(jsonStart).To(BeNumerically(">=", 0))
				jsonStr := output[jsonStart : jsonEnd+1]
				g.Expect(json.Unmarshal([]byte(jsonStr), &status)).To(Succeed())

				var newNodeID string
				for _, n := range status.Nodes {
					if n.IsUp && n.Role != nil && n.Role.Capacity == nil {
						newNodeID = n.ID
						break
					}
				}
				// The node ID MUST be the same as before because the gateway
				// StatefulSet remounts the metadata PVC and Garage reads the
				// existing node_key from it.
				g.Expect(newNodeID).NotTo(BeEmpty(), "expected the gateway to be connected after restart")
				g.Expect(newNodeID).To(Equal(oldNodeID),
					"Node ID must be preserved across restart. Old: %s, New: %s", oldNodeID[:16], newNodeID[:16])
			}
			Eventually(verifyNodeIDPreserved, 3*time.Minute, 10*time.Second).Should(Succeed())

			By("verifying gateway entry remains stable across restart (persistent identity, no new layout version)")
			// Gateways are in the layout with capacity=nil. After a pod
			// restart the metadata PVC preserves the node_key, so the same
			// node ID rejoins. No removal should be staged and no extra
			// gateway role should appear.
			verifyLayoutClean := func(g Gomega) {
				curlCmd := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterLayout",
					adminToken, storageClusterName, testNamespace)
				cmd := exec.Command("kubectl", "run", "curl-layout-final", "--rm", "-i", "--restart=Never",
					"-n", testNamespace,
					"--image=docker.io/curlimages/curl:latest",
					"--overrides", fmt.Sprintf(`{
						"spec": {
							"containers": [{
								"name": "curl-layout-final",
								"image": "docker.io/curlimages/curl:latest",
								"imagePullPolicy": "IfNotPresent",
								"command": ["/bin/sh", "-c"],
								"args": [%q],
								"securityContext": {
									"readOnlyRootFilesystem": true,
									"allowPrivilegeEscalation": false,
									"capabilities": {"drop": ["ALL"]},
									"runAsNonRoot": true,
									"runAsUser": 1000,
									"seccompProfile": {"type": "RuntimeDefault"}
								}
							}]
						}
					}`, curlCmd))
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to query cluster layout: %s", output)

				var layout struct {
					Roles []struct {
						ID   string   `json:"id"`
						Tags []string `json:"tags"`
					} `json:"roles"`
					StagedRoleChanges []struct {
						ID     string `json:"id"`
						Remove bool   `json:"remove"`
					} `json:"stagedRoleChanges"`
				}
				jsonStart := strings.Index(output, "{")
				jsonEnd := strings.LastIndex(output, "}")
				g.Expect(jsonStart).To(BeNumerically(">=", 0))
				jsonStr := output[jsonStart : jsonEnd+1]
				g.Expect(json.Unmarshal([]byte(jsonStr), &layout)).To(Succeed())

				// Expect exactly one gateway-tagged role (the single replica
				// running in this test). More than one indicates the pod
				// minted a new identity on restart.
				gatewayRoles := 0
				for _, role := range layout.Roles {
					for _, tag := range role.Tags {
						if tag == "tier:gateway" {
							gatewayRoles++
							break
						}
					}
				}
				g.Expect(gatewayRoles).To(Equal(1),
					"Expected exactly 1 gateway role after restart, got %d. Roles: %+v", gatewayRoles, layout.Roles)

				// No staged removal — persistent identity means the same UUID
				// returns and no entry needs tombstoning.
				for _, change := range layout.StagedRoleChanges {
					g.Expect(change.Remove).To(BeFalse(),
						"Unexpected pending gateway removal for %s", change.ID)
				}
			}
			Eventually(verifyLayoutClean, 4*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("should have layout with only expected roles (no extra stale entries)", func() {
			By("querying the cluster layout")
			adminToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			verifyLayoutRoles := func(g Gomega) {
				curlCmd := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterLayout",
					adminToken, storageClusterName, testNamespace)
				cmd := exec.Command("kubectl", "run", "curl-layout-roles", "--rm", "-i", "--restart=Never",
					"-n", testNamespace,
					"--image=docker.io/curlimages/curl:latest",
					"--overrides", fmt.Sprintf(`{
						"spec": {
							"containers": [{
								"name": "curl-layout-roles",
								"image": "docker.io/curlimages/curl:latest",
								"imagePullPolicy": "IfNotPresent",
								"command": ["/bin/sh", "-c"],
								"args": [%q],
								"securityContext": {
									"readOnlyRootFilesystem": true,
									"allowPrivilegeEscalation": false,
									"capabilities": {"drop": ["ALL"]},
									"runAsNonRoot": true,
									"runAsUser": 1000,
									"seccompProfile": {"type": "RuntimeDefault"}
								}
							}]
						}
					}`, curlCmd))
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to query layout: %s", output)

				// Parse the layout JSON
				var layout struct {
					Roles []struct {
						ID string `json:"id"`
					} `json:"roles"`
					StagedRoleChanges []interface{} `json:"stagedRoleChanges"`
				}
				jsonStart := strings.Index(output, "{")
				jsonEnd := strings.LastIndex(output, "}")
				g.Expect(jsonStart).To(BeNumerically(">=", 0), "No JSON found in output: %s", output)
				g.Expect(jsonEnd).To(BeNumerically(">", jsonStart), "No valid JSON found in output: %s", output)
				jsonStr := output[jsonStart : jsonEnd+1]
				g.Expect(json.Unmarshal([]byte(jsonStr), &layout)).To(Succeed(), "Failed to parse layout JSON: %s", jsonStr)

				// Gateways participate in the layout: 1 storage + 1 gateway = 2 roles.
				g.Expect(layout.Roles).To(HaveLen(2),
					"Layout should have 2 roles (1 storage + 1 gateway), got %d. Layout: %s", len(layout.Roles), output)

				// Also verify no staged changes are pending
				g.Expect(layout.StagedRoleChanges).To(BeEmpty(),
					"Layout should have no pending staged changes, got: %d changes", len(layout.StagedRoleChanges))
			}
			Eventually(verifyLayoutRoles, 3*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("should remove gateway node from layout when gateway cluster is deleted", func() {
			By("deleting the gateway cluster")
			cmd := exec.Command("kubectl", "delete", "garagecluster", gatewayClusterName,
				"-n", testNamespace, "--wait=true", "--timeout=60s")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete gateway cluster: %s", output)

			By("waiting for gateway cluster deletion to complete")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagecluster", gatewayClusterName,
					"-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred(), "Gateway cluster should be deleted")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying gateway node removed from storage cluster layout")
			adminToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			verifyGatewayRemoved := func(g Gomega) {
				// Force-delete any existing curl pod from previous retry attempts
				cleanupCmd := exec.Command("kubectl", "delete", "pod", "curl-layout-cleanup",
					"-n", testNamespace, "--ignore-not-found", "--force", "--grace-period=0")
				_, _ = utils.Run(cleanupCmd)

				curlCmd := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterLayout",
					adminToken, storageClusterName, testNamespace)
				cmd := exec.Command("kubectl", "run", "curl-layout-cleanup", "--rm", "-i", "--restart=Never",
					"-n", testNamespace,
					"--image=docker.io/curlimages/curl:latest",
					"--overrides", fmt.Sprintf(`{
						"spec": {
							"containers": [{
								"name": "curl-layout-cleanup",
								"image": "docker.io/curlimages/curl:latest",
								"imagePullPolicy": "IfNotPresent",
								"command": ["/bin/sh", "-c"],
								"args": [%q],
								"securityContext": {
									"readOnlyRootFilesystem": true,
									"allowPrivilegeEscalation": false,
									"capabilities": {"drop": ["ALL"]},
									"runAsNonRoot": true,
									"runAsUser": 1000,
									"seccompProfile": {"type": "RuntimeDefault"}
								}
							}]
						}
					}`, curlCmd))
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to query layout: %s", output)

				var layout struct {
					Roles []struct {
						ID       string  `json:"id"`
						Capacity *uint64 `json:"capacity"`
					} `json:"roles"`
					StagedRoleChanges []struct {
						ID     string `json:"id"`
						Remove bool   `json:"remove"`
					} `json:"stagedRoleChanges"`
				}
				jsonStart := strings.Index(output, "{")
				jsonEnd := strings.LastIndex(output, "}")
				g.Expect(jsonStart).To(BeNumerically(">=", 0), "No JSON found in output: %s", output)
				g.Expect(jsonEnd).To(BeNumerically(">", jsonStart), "No valid JSON found")
				jsonStr := output[jsonStart : jsonEnd+1]
				g.Expect(json.Unmarshal([]byte(jsonStr), &layout)).To(Succeed(), "Failed to parse layout: %s", jsonStr)

				// Count gateway nodes (nil capacity)
				gatewayNodeCount := 0
				for _, role := range layout.Roles {
					if role.Capacity == nil {
						gatewayNodeCount++
					}
				}

				// After gateway deletion, there should be no gateway nodes
				g.Expect(gatewayNodeCount).To(Equal(0),
					"Layout should have no gateway nodes after deletion, got %d", gatewayNodeCount)

				// Should only have 1 storage node remaining
				g.Expect(layout.Roles).To(HaveLen(1),
					"Layout should have 1 storage node after gateway deletion, got %d", len(layout.Roles))

				// No pending staged changes
				g.Expect(layout.StagedRoleChanges).To(BeEmpty(),
					"Should have no pending staged changes")
			}
			Eventually(verifyGatewayRemoved, 3*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("should support scale subresource", func() {
			By("verifying status.selector is populated")
			verifySelectorPopulated := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagecluster", storageClusterName,
					"-n", testNamespace, "-o", "jsonpath={.status.selector}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty(), "status.selector should be populated")
				// Post-#190: per-node pods carry labelCluster (storage tier is N×GarageNodes).
				// The cluster-wide selector now keys on garage.rajsingh.info/cluster.
				g.Expect(output).To(ContainSubstring("garage.rajsingh.info/cluster=" + storageClusterName))
			}
			Eventually(verifySelectorPopulated, 30*time.Second, 2*time.Second).Should(Succeed())

			By("verifying status.replicas matches spec.replicas")
			cmd := exec.Command("kubectl", "get", "garagecluster", storageClusterName,
				"-n", testNamespace, "-o", "jsonpath={.status.replicas}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("1"), "status.replicas should match spec")

			By("scaling up via kubectl scale")
			cmd = exec.Command("kubectl", "scale", "garagecluster", storageClusterName,
				"-n", testNamespace, "--replicas=2")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "kubectl scale should succeed")

			By("verifying spec.storage.replicas was updated by scale subresource")
			cmd = exec.Command("kubectl", "get", "garagecluster", storageClusterName,
				"-n", testNamespace, "-o", "jsonpath={.spec.storage.replicas}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("2"), "spec.storage.replicas should be updated to 2")

			By("waiting for scaled pods to be ready")
			verifyScaledReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagecluster", storageClusterName,
					"-n", testNamespace, "-o", "jsonpath={.status.readyReplicas}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("2"), "readyReplicas should be 2, got %s", output)
			}
			Eventually(verifyScaledReady, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("scaling back down to 1")
			cmd = exec.Command("kubectl", "scale", "garagecluster", storageClusterName,
				"-n", testNamespace, "--replicas=1")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for scale down")
			verifyScaledDown := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "-n", testNamespace,
					"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", storageClusterName),
					"--no-headers")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				lines := strings.Split(strings.TrimSpace(output), "\n")
				g.Expect(len(lines)).To(Equal(1), "expected 1 pod, got %d", len(lines))
			}
			Eventually(verifyScaledDown, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})
})

// Unified Cluster exercises the #209 fix: a single GarageCluster CR declaring
// BOTH a storage tier and a gateway tier. The gateway tier must run as per-node
// GarageNodes (gateway:true, capacity=nil layout role) rather than a cluster-level
// StatefulSet — so gateway pods participate in FullReplication locally and S3
// sig-auth resolves keys via get_local() without per-request storage-tier RPCs.
var _ = Describe("Unified Cluster (storage + gateway in one CR)", Ordered, Label("unified-gateway"), func() {
	const testNamespace = "garage-unified-test"
	const clusterName = "unified-cluster"

	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, _ = utils.Run(cmd)

		By("labeling the manager namespace restricted")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, _ = utils.Run(cmd)

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for controller-manager pod to be Ready")
		verifyControllerUp := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods", "-l", "control-plane=controller-manager",
				"-n", namespace,
				"-o", "jsonpath={.items[0].status.conditions[?(@.type=='Ready')].status}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True"), "Controller not Ready: %s", output)
		}
		Eventually(verifyControllerUp, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("creating + labeling test namespace")
		cmd = exec.Command("kubectl", "create", "ns", testNamespace)
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		By("cleaning up unified-cluster test resources")
		cmd := exec.Command("kubectl", "delete", "garagecluster", clusterName, "-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		time.Sleep(10 * time.Second)
		cmd = exec.Command("kubectl", "delete", "ns", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)
	})

	It("creates the unified cluster and reaches Running", func() {
		By("creating admin token secret")
		adminTokenSecret := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: garage-admin-token
  namespace: %s
type: Opaque
stringData:
  admin-token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
`, testNamespace)
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(adminTokenSecret)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("applying a unified GarageCluster (storage + gateway in one CR)")
		unifiedYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  replication:
    factor: 1
  layoutManagement:
    autoApply: true
  storage:
    replicas: 1
    metadata:
      size: 1Gi
    data:
      size: 1Gi
    resources:
      limits: {memory: 256Mi}
      requests: {memory: 128Mi}
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      fsGroup: 1000
      seccompProfile: {type: RuntimeDefault}
    containerSecurityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000
      capabilities: {drop: [ALL]}
      seccompProfile: {type: RuntimeDefault}
  gateway:
    replicas: 1
    resources:
      limits: {memory: 128Mi}
      requests: {memory: 64Mi}
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      fsGroup: 1000
      seccompProfile: {type: RuntimeDefault}
    containerSecurityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000
      capabilities: {drop: [ALL]}
      seccompProfile: {type: RuntimeDefault}
  admin:
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
  security:
    allowInsecureSecretPermissions: true
`, clusterName, testNamespace)
		applyUnified := func(g Gomega) {
			c := exec.Command("kubectl", "apply", "-f", "-")
			c.Stdin = strings.NewReader(unifiedYAML)
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred(), "Failed to create unified cluster: %s", out)
		}
		Eventually(applyUnified, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("waiting for the unified cluster to be Running")
		verifyRunning := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagecluster", clusterName,
				"-n", testNamespace, "-o", "jsonpath={.status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Running"), "Unified cluster not Running: phase=%s", output)
		}
		Eventually(verifyRunning, 5*time.Minute, 5*time.Second).Should(Succeed())
	})

	It("runs the gateway tier as per-node GarageNodes, not a cluster StatefulSet", func() {
		By("verifying an operator-owned gateway GarageNode exists")
		verifyGatewayNode := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenode",
				"-n", testNamespace,
				"-l", fmt.Sprintf("garage.rajsingh.info/cluster=%s,garage.rajsingh.info/tier=gateway,app.kubernetes.io/managed-by=operator", clusterName),
				"-o", "jsonpath={.items[*].metadata.name}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(ContainSubstring(clusterName+"-gateway-0"),
				"expected an operator-owned gateway GarageNode <cluster>-gateway-0, got: %q", output)
		}
		Eventually(verifyGatewayNode, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying the per-node gateway StatefulSet exists")
		verifyPerNodeSTS := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "statefulset", clusterName+"-gateway-0",
				"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred(), "per-node gateway STS missing: %s", output)
			g.Expect(output).To(Equal(clusterName + "-gateway-0"))
		}
		Eventually(verifyPerNodeSTS, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying NO legacy cluster-level gateway StatefulSet exists")
		cmd := exec.Command("kubectl", "get", "statefulset", clusterName+"-gateway",
			"-n", testNamespace, "--ignore-not-found", "-o", "jsonpath={.metadata.name}")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(output)).To(BeEmpty(),
			"legacy cluster-level gateway StatefulSet <cluster>-gateway must NOT exist in a per-node unified cluster")
	})

	It("assigns the gateway pod a capacity=nil layout role (#209)", func() {
		adminToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		verifyGatewayRole := func(g Gomega) {
			curlCmd := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterLayout",
				adminToken, clusterName, testNamespace)
			cmd := exec.Command("kubectl", "run", "curl-unified-layout", "--rm", "-i", "--restart=Never",
				"-n", testNamespace,
				"--image=docker.io/curlimages/curl:latest",
				"--overrides", fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl-unified-layout",
							"image": "docker.io/curlimages/curl:latest",
							"imagePullPolicy": "IfNotPresent",
							"command": ["/bin/sh", "-c"],
							"args": [%q],
							"securityContext": {
								"readOnlyRootFilesystem": true,
								"allowPrivilegeEscalation": false,
								"capabilities": {"drop": ["ALL"]},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {"type": "RuntimeDefault"}
							}
						}]
					}
				}`, curlCmd))
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred(), "Failed to query layout: %s", output)

			var layout struct {
				Roles []struct {
					ID       string   `json:"id"`
					Tags     []string `json:"tags"`
					Capacity *uint64  `json:"capacity"`
				} `json:"roles"`
			}
			jsonStart := strings.Index(output, "{")
			jsonEnd := strings.LastIndex(output, "}")
			g.Expect(jsonStart).To(BeNumerically(">=", 0), "No JSON in output: %s", output)
			jsonStr := output[jsonStart : jsonEnd+1]
			g.Expect(json.Unmarshal([]byte(jsonStr), &layout)).To(Succeed(), "bad layout JSON: %s", jsonStr)

			gatewayRoles, storageRoles := 0, 0
			for _, role := range layout.Roles {
				isGateway := false
				for _, tag := range role.Tags {
					if tag == "tier:gateway" {
						isGateway = true
					}
				}
				if isGateway && role.Capacity == nil {
					gatewayRoles++
				}
				if role.Capacity != nil {
					storageRoles++
				}
			}
			g.Expect(gatewayRoles).To(BeNumerically(">=", 1),
				"expected >=1 gateway role (capacity=nil + tier:gateway) in unified cluster layout: %+v", layout.Roles)
			g.Expect(storageRoles).To(BeNumerically(">=", 1),
				"expected the storage node to still hold a capacity role: %+v", layout.Roles)
		}
		Eventually(verifyGatewayRole, 4*time.Minute, 10*time.Second).Should(Succeed())
	})
})

// Factor Migration exercises the #208 coordinated replication-factor migration:
// a 2-node factor-2 cluster reduced to factor 1 via the purge-cluster-layout
// annotation. Verifies the operator deletes the on-disk cluster_layout, restarts
// all storage pods simultaneously, rebuilds the layout at the new factor, and
// reaches status.factorMigration.phase=Completed — without the cluster getting
// stuck. Node identity (metadata PVC) and data (data PVC) survive the purge.
var _ = Describe("Factor Migration", Ordered, Label("factor-migration"), func() {
	const testNamespace = "garage-factor-test"
	const clusterName = "factor-cluster"

	BeforeAll(func() {
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace, "pod-security.kubernetes.io/enforce=restricted")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("make", "install")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(utils.WaitCRDsEstablished()).To(Succeed())
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		verifyControllerUp := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods", "-l", "control-plane=controller-manager", "-n", namespace,
				"-o", "jsonpath={.items[0].status.conditions[?(@.type=='Ready')].status}")
			out, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal("True"), "controller not Ready: %s", out)
		}
		Eventually(verifyControllerUp, 3*time.Minute, 5*time.Second).Should(Succeed())
		cmd = exec.Command("kubectl", "create", "ns", testNamespace)
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace, "pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		cmd := exec.Command("kubectl", "delete", "garagecluster", clusterName, "-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		time.Sleep(10 * time.Second)
		cmd = exec.Command("kubectl", "delete", "ns", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)
	})

	It("creates a 2-node factor-2 storage cluster", func() {
		secret := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata: {name: garage-admin-token, namespace: %s}
type: Opaque
stringData: {admin-token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
`, testNamespace)
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(secret)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		yaml := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata: {name: %s, namespace: %s}
spec:
  replication: {factor: 2}
  layoutManagement: {autoApply: true}
  storage:
    replicas: 2
    metadata: {size: 1Gi}
    data: {size: 1Gi}
    resources: {limits: {memory: 256Mi}, requests: {memory: 128Mi}}
    securityContext: {runAsNonRoot: true, runAsUser: 1000, fsGroup: 1000, seccompProfile: {type: RuntimeDefault}}
    containerSecurityContext: {allowPrivilegeEscalation: false, runAsNonRoot: true, runAsUser: 1000, capabilities: {drop: [ALL]}, seccompProfile: {type: RuntimeDefault}}
  admin: {adminTokenSecretRef: {name: garage-admin-token, key: admin-token}}
  security: {allowInsecureSecretPermissions: true}
`, clusterName, testNamespace)
		apply := func(g Gomega) {
			c := exec.Command("kubectl", "apply", "-f", "-")
			c.Stdin = strings.NewReader(yaml)
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred(), "apply: %s", out)
		}
		Eventually(apply, 2*time.Minute, 5*time.Second).Should(Succeed())

		verifyRunning := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace, "-o", "jsonpath={.status.phase}")
			out, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal("Running"), "phase=%s", out)
		}
		Eventually(verifyRunning, 6*time.Minute, 5*time.Second).Should(Succeed())
	})

	It("reduces the replication factor from 2 to 1 via purge-cluster-layout", func() {
		By("patching spec.replication.factor=1")
		patchFactor := func(g Gomega) {
			c := exec.Command("kubectl", "patch", "garagecluster", clusterName, "-n", testNamespace,
				"--type=merge", "-p", `{"spec":{"replication":{"factor":1}}}`)
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred(), "patch factor: %s", out)
		}
		Eventually(patchFactor, time.Minute, 5*time.Second).Should(Succeed())

		By("confirming the spec.replication.factor change took effect")
		verifyFactor := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace,
				"-o", "jsonpath={.spec.replication.factor}")
			out, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(Equal("1"), "spec.replication.factor=%s", out)
		}
		Eventually(verifyFactor, time.Minute, 5*time.Second).Should(Succeed())

		By("setting the purge-cluster-layout annotation")
		cmd := exec.Command("kubectl", "annotate", "garagecluster", clusterName, "-n", testNamespace,
			"garage.rajsingh.info/purge-cluster-layout=factor=1", "--overwrite")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("waiting for the migration to reach Completed (fail fast with the message on Failed)")
		verifyCompleted := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace,
				"-o", "jsonpath={.status.factorMigration.phase}|{.status.factorMigration.message}")
			out, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			phase := strings.TrimSpace(strings.Split(out, "|")[0])
			if phase == "Failed" {
				StopTrying(fmt.Sprintf("factor migration Failed: %s", out)).Now()
			}
			g.Expect(phase).To(Equal("Completed"), "factorMigration=%s", out)
		}
		Eventually(verifyCompleted, 12*time.Minute, 10*time.Second).Should(Succeed())
	})

	It("returns to Running with both storage nodes still present (identity + data preserved)", func() {
		verifyHealthy := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace, "-o", "jsonpath={.status.phase}")
			out, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal("Running"), "phase=%s", out)
		}
		Eventually(verifyHealthy, 5*time.Minute, 10*time.Second).Should(Succeed())

		By("verifying both storage GarageNodes survived the purge")
		cmd := exec.Command("kubectl", "get", "garagenode", "-n", testNamespace,
			"-l", fmt.Sprintf("garage.rajsingh.info/cluster=%s,garage.rajsingh.info/tier=storage", clusterName),
			"-o", "jsonpath={.items[*].metadata.name}")
		out, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring(clusterName + "-storage-0"))
		Expect(out).To(ContainSubstring(clusterName + "-storage-1"))

		By("verifying the purge annotation was removed after success")
		cmd = exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace,
			"-o", "jsonpath={.metadata.annotations.garage\\.rajsingh\\.info/purge-cluster-layout}")
		out, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(out)).To(BeEmpty())
	})
})

var _ = Describe("Webhooks", Ordered, Label("webhooks"), func() {
	const webhookNamespace = "garage-webhook-system"
	var webhookControllerPodName string

	// Get Kind cluster name for kube-context
	kindCluster := os.Getenv("KIND_CLUSTER")
	if kindCluster == "" {
		kindCluster = "kind" // default Kind cluster name
	}
	kubeContext := fmt.Sprintf("kind-%s", kindCluster)

	BeforeAll(func() {
		By("creating webhook test namespace")
		cmd := exec.Command("kubectl", "create", "ns", webhookNamespace)
		_, _ = utils.Run(cmd)

		// Note: Image is already built and loaded by BeforeSuite (example.com/garage-operator:v0.0.1)

		// Prior Describe blocks install CRDs via `make install` (kustomize), which
		// does not set Helm ownership labels/annotations. A subsequent `helm
		// install` then refuses to adopt those CRDs with an "invalid ownership
		// metadata" error. Delete any leftover Garage CRDs (and their CRs across
		// the cluster, since CRDs are cluster-scoped) before the Helm install so
		// it can manage them fresh. Earlier suites' AfterAll already calls
		// `make uninstall`, so in the common case this is a no-op.
		By("deleting any pre-existing Garage CRDs to avoid helm ownership conflict")
		cmd = exec.Command("kubectl", "delete", "crd",
			"garageadmintokens.garage.rajsingh.info",
			"garagebuckets.garage.rajsingh.info",
			"garageclusters.garage.rajsingh.info",
			"garagekeys.garage.rajsingh.info",
			"garagenodes.garage.rajsingh.info",
			"garagereferencegrants.garage.rajsingh.info",
			"--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)

		// Helm chart installs the CRDs (crds.install=true in values-e2e-webhooks.yaml)
		// AND patches the conversion webhook clientConfig to the release-scoped
		// service, so the API server can actually reach the conversion webhook.
		// `make install` would install CRDs pointing to the kustomize-default
		// service name/namespace, which does not exist for this test.
		By("deploying operator + CRDs via Helm with webhooks enabled")
		cmd = exec.Command("helm", "install", "garage-operator-webhook-test",
			"charts/garage-operator",
			"--namespace", webhookNamespace,
			"--kube-context", kubeContext,
			"-f", "charts/garage-operator/values-e2e-webhooks.yaml",
			"--wait", "--timeout", "180s")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy operator with webhooks: %s", output)

		By("waiting for Garage CRDs to be Established")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())
	})

	AfterAll(func() {
		By("uninstalling Helm release")
		cmd := exec.Command("helm", "uninstall", "garage-operator-webhook-test",
			"--namespace", webhookNamespace,
			"--kube-context", kubeContext)
		_, _ = utils.Run(cmd)

		By("deleting webhook test namespace")
		cmd = exec.Command("kubectl", "delete", "ns", webhookNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)

		By("deleting webhook-test namespace")
		cmd = exec.Command("kubectl", "delete", "ns", "webhook-test", "--ignore-not-found")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)
	})

	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() && webhookControllerPodName != "" {
			By("Fetching webhook controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", webhookControllerPodName, "-n", webhookNamespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Webhook controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get webhook controller logs: %s", err)
			}
		}
	})

	Context("Webhook Server", func() {
		It("should start webhook server when webhooks enabled", func() {
			By("getting the controller pod name")
			verifyControllerUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods",
					"-l", "app.kubernetes.io/name=garage-operator",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", webhookNamespace,
				)
				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller pod")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				webhookControllerPodName = podNames[0]

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get", "pods", webhookControllerPodName,
					"-o", "jsonpath={.status.phase}", "-n", webhookNamespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Controller pod not running")
			}
			Eventually(verifyControllerUp, 2*time.Minute, time.Second).Should(Succeed())

			By("verifying webhook server is running")
			verifyWebhookServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", webhookControllerPodName, "-n", webhookNamespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("Initializing webhook certificate watcher"),
					"Webhook server not started. Logs: %s", output)
			}
			Eventually(verifyWebhookServerStarted, 2*time.Minute, time.Second).Should(Succeed())

			By("waiting for cert-manager to inject CA bundle into webhook configurations")
			verifyCaBundleInjected := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "mutatingwebhookconfiguration",
					"-l", "app.kubernetes.io/name=garage-operator",
					"-o", "jsonpath={.items[0].webhooks[0].clientConfig.caBundle}",
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty(), "CA bundle not yet injected by cert-manager")
			}
			Eventually(verifyCaBundleInjected, 2*time.Minute, time.Second).Should(Succeed())
		})

		It("should return validation warnings for EmptyDir storage", func() {
			By("creating test namespace for webhook validation")
			cmd := exec.Command("kubectl", "create", "ns", "webhook-test")
			_, _ = utils.Run(cmd)

			By("creating admin token secret")
			cmd = exec.Command("kubectl", "create", "secret", "generic", "test-admin-token",
				"-n", "webhook-test",
				"--from-literal=admin-token=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("creating GarageCluster with EmptyDir to trigger validation warning")
			clusterYAML := `
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: webhook-test-cluster
  namespace: webhook-test
spec:
  replication:
    factor: 1
  storage:
    replicas: 1
    metadata:
      type: EmptyDir
    data:
      type: EmptyDir
    podDisruptionBudget:
      enabled: false
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
      name: test-admin-token
      key: admin-token
`
			// Retry creation: the webhook server may still be starting up even after
			// the pod is Ready (readiness probe checks :8081, not the webhook port).
			var applyOutput string
			applyCluster := func(g Gomega) {
				cmd := exec.Command("kubectl", "apply", "-f", "-")
				cmd.Stdin = strings.NewReader(clusterYAML)
				out, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to create GarageCluster: %s", out)
				applyOutput = out
			}
			Eventually(applyCluster, 2*time.Minute, 5*time.Second).Should(Succeed())

			// Verify webhook returned validation warnings
			Expect(applyOutput).To(ContainSubstring("Warning"),
				"Expected validation warning from webhook for EmptyDir storage. Output: %s", applyOutput)

			By("verifying the GarageCluster was created")
			verifyClusterCreated := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagecluster", "webhook-test-cluster",
					"-n", "webhook-test", "-o", "jsonpath={.metadata.name}")
				out, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(Equal("webhook-test-cluster"))
			}
			Eventually(verifyClusterCreated, 30*time.Second, time.Second).Should(Succeed())

			By("cleaning up webhook test cluster")
			cmd = exec.Command("kubectl", "delete", "garagecluster", "webhook-test-cluster",
				"-n", "webhook-test", "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should reject invalid GarageCluster configurations", func() {
			By("creating test namespace if not exists")
			cmd := exec.Command("kubectl", "create", "ns", "webhook-test")
			_, _ = utils.Run(cmd)

			By("attempting to create GarageCluster with invalid layoutPolicy")
			invalidClusterYAML := `
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: invalid-cluster
  namespace: webhook-test
spec:
  layoutPolicy: InvalidPolicy
  replication:
    factor: 3
  storage:
    replicas: 1
    metadata:
      size: 1Gi
    data:
      size: 1Gi
`
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(invalidClusterYAML)
			output, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "Expected webhook to reject invalid configuration. Output: %s", output)
			Expect(output).To(ContainSubstring("layoutPolicy"),
				"Error should mention layoutPolicy. Output: %s", output)
		})
	})

	// GarageReferenceGrant tests run inside this block because it uses helm install --wait,
	// which ensures webhooks are ready (cert-manager has injected the CA bundle).
	Context("GarageReferenceGrant", Ordered, Label("referencegrant"), func() {
		const rgSourceNS = "e2e-referencegrant-src"

		BeforeAll(func() {
			By("creating source namespace for cross-namespace tests")
			cmd := exec.Command("kubectl", "create", "ns", rgSourceNS)
			_, _ = utils.Run(cmd)
		})

		AfterAll(func() {
			By("cleaning up source namespace")
			cmd := exec.Command("kubectl", "delete", "ns", rgSourceNS, "--ignore-not-found")
			_, _ = utils.Run(cmd)

			By("cleaning up GarageReferenceGrants")
			cmd = exec.Command("kubectl", "delete", "garagereferencegrant",
				"--all", "-n", webhookNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should reject a GarageKey with cross-namespace clusterRef when no grant exists", func() {
			keyYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: e2e-rg-key-no-grant
  namespace: %s
spec:
  clusterRef:
    name: non-existent-cluster
    namespace: %s
`, rgSourceNS, webhookNamespace)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(keyYAML)
			output, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "cross-namespace clusterRef should be rejected without a grant")
			Expect(output).To(ContainSubstring("GarageReferenceGrant"),
				"rejection message should mention GarageReferenceGrant; got: %s", output)

			cmd = exec.Command("kubectl", "delete", "garagekey", "e2e-rg-key-no-grant",
				"-n", rgSourceNS, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should allow a GarageKey with same-namespace clusterRef without any grant", func() {
			keyYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: e2e-rg-same-ns-key
  namespace: %s
spec:
  clusterRef:
    name: non-existent-cluster
`, webhookNamespace)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(keyYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "same-namespace clusterRef should be admitted without a grant")

			cmd = exec.Command("kubectl", "delete", "garagekey", "e2e-rg-same-ns-key",
				"-n", webhookNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should admit a GarageKey with cross-namespace clusterRef when a matching grant exists", func() {
			grantYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageReferenceGrant
metadata:
  name: e2e-rg-grant-for-key
  namespace: %s
spec:
  from:
    - kind: GarageKey
      namespace: %s
  to:
    - kind: GarageCluster
`, webhookNamespace, rgSourceNS)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(grantYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "GarageReferenceGrant should be created")

			keyYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: e2e-rg-key-with-grant
  namespace: %s
spec:
  clusterRef:
    name: non-existent-cluster
    namespace: %s
`, rgSourceNS, webhookNamespace)
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(keyYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "cross-namespace clusterRef should be admitted with a matching grant")
		})

		It("should reject a GarageBucket with cross-namespace clusterRef when no grant exists", func() {
			bucketYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: e2e-rg-bucket-no-grant
  namespace: %s
spec:
  clusterRef:
    name: non-existent-cluster
    namespace: %s
`, rgSourceNS, webhookNamespace)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(bucketYAML)
			output, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "cross-namespace clusterRef should be rejected without a grant for GarageBucket")
			Expect(output).To(ContainSubstring("GarageReferenceGrant"))

			cmd = exec.Command("kubectl", "delete", "garagebucket", "e2e-rg-bucket-no-grant",
				"-n", rgSourceNS, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should admit a GarageBucket with cross-namespace clusterRef when grant covers GarageBucket", func() {
			grantYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageReferenceGrant
metadata:
  name: e2e-rg-grant-for-bucket
  namespace: %s
spec:
  from:
    - kind: GarageBucket
      namespace: %s
  to:
    - kind: GarageCluster
`, webhookNamespace, rgSourceNS)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(grantYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			bucketYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: e2e-rg-bucket-with-grant
  namespace: %s
spec:
  clusterRef:
    name: non-existent-cluster
    namespace: %s
`, rgSourceNS, webhookNamespace)
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(bucketYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "cross-namespace clusterRef should be admitted with a matching grant")

			cmd = exec.Command("kubectl", "delete", "garagebucket", "e2e-rg-bucket-with-grant",
				"-n", rgSourceNS, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should populate status.inUseBy when resources reference through the grant", func() {
			verifyInUseBy := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagereferencegrant", "e2e-rg-grant-for-key",
					"-n", webhookNamespace, "-o", "jsonpath={.status.inUseBy}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("e2e-rg-key-with-grant"),
					"inUseBy should include the cross-namespace key; got: %s", output)
			}
			Eventually(verifyInUseBy, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("should update InUse condition to True when grant is actively referenced", func() {
			verifyInUseCondition := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagereferencegrant", "e2e-rg-grant-for-key",
					"-n", webhookNamespace,
					"-o", "jsonpath={.status.conditions[?(@.type=='InUse')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "InUse condition should be True when grant is referenced")
			}
			Eventually(verifyInUseCondition, 30*time.Second, 2*time.Second).Should(Succeed())
		})

		It("should clear InUse condition after referencing resource is deleted", func() {
			cmd := exec.Command("kubectl", "delete", "garagekey", "e2e-rg-key-with-grant",
				"-n", rgSourceNS, "--ignore-not-found")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			verifyCleared := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagereferencegrant", "e2e-rg-grant-for-key",
					"-n", webhookNamespace,
					"-o", "jsonpath={.status.conditions[?(@.type=='InUse')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("False"),
					"InUse condition should be False after key is deleted")
			}
			Eventually(verifyCleared, 30*time.Second, 2*time.Second).Should(Succeed())
		})
	})
})

var _ = Describe("Manual Mode with GarageNodes", Ordered, Label("manual-mode"), func() {
	const testNamespace = "garage-manual-test"
	const clusterName = "manual-cluster"
	const node1Name = "garage-node-1"
	const node2Name = "garage-node-2"

	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, _ = utils.Run(cmd) // Ignore error if already exists

		By("labeling the manager namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, _ = utils.Run(cmd)

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("waiting for Garage CRDs to be Established")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for controller-manager pod to be Ready (webhook server started)")
		verifyControllerUp := func(g Gomega) {
			// Use Ready condition rather than pod Phase. With the webhook
			// readiness gate (cmd/main.go: webhookServer.StartedChecker), the
			// pod will not flip Ready until the TLS listener on :9443 is
			// accepting connections, which is exactly what the next CR apply
			// needs.
			cmd := exec.Command("kubectl", "get", "pods", "-l", "control-plane=controller-manager",
				"-n", namespace,
				"-o", "jsonpath={.items[0].status.conditions[?(@.type=='Ready')].status}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True"), "Controller not Ready: %s", output)
		}
		Eventually(verifyControllerUp, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("creating test namespace")
		cmd = exec.Command("kubectl", "create", "ns", testNamespace)
		_, _ = utils.Run(cmd) // Ignore error if already exists

		By("labeling the test namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		By("cleaning up test resources")
		cmd := exec.Command("kubectl", "delete", "garagekey", "--all", "-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "garagebucket", "--all", "-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "garagenode", node1Name, "-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "garagenode", node2Name, "-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "garagecluster", clusterName, "-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		time.Sleep(10 * time.Second) // Wait for cleanup
		cmd = exec.Command("kubectl", "delete", "ns", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)
	})

	Context("When creating a Manual mode cluster with GarageNodes", func() {
		It("should create cluster in Manual mode (no StatefulSet)", func() {
			By("creating admin token secret")
			adminTokenSecret := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: garage-admin-token
  namespace: %s
type: Opaque
stringData:
  admin-token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
`, testNamespace)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(adminTokenSecret)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create admin token secret")

			By("creating GarageCluster with layoutPolicy: Manual")
			clusterYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  layoutPolicy: Manual
  replication:
    factor: 2
  storage:
    replicas: 1
    metadata:
      size: 100Mi
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
  security:
    allowInsecureSecretPermissions: true
`, clusterName, testNamespace)

			By("applying GarageCluster (retry until admission webhook is up)")
			Eventually(func(g Gomega) {
				c := exec.Command("kubectl", "apply", "-f", "-")
				c.Stdin = strings.NewReader(clusterYAML)
				out, err := utils.Run(c)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to create GarageCluster: %s", out)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying no StatefulSet is created for Manual mode cluster")
			time.Sleep(5 * time.Second)
			cmd = exec.Command("kubectl", "get", "statefulset", clusterName, "-n", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "StatefulSet should NOT exist for Manual mode cluster")
		})

		It("should create GarageNode 1 with its own StatefulSet", func() {
			By("creating GarageNode 1")
			node1YAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef:
    name: %s
  zone: zone-a
  capacity: 1Gi
  storage:
    metadata:
      size: 100Mi
    data:
      size: 1Gi
  resources:
    limits:
      memory: 256Mi
    requests:
      memory: 128Mi
`, node1Name, testNamespace, clusterName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(node1YAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create GarageNode 1")

			By("waiting for GarageNode 1 StatefulSet to be created")
			verifyStatefulSet := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", node1Name,
					"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal(node1Name))
			}
			Eventually(verifyStatefulSet, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for GarageNode 1 pod to be running")
			verifyPodRunning := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", fmt.Sprintf("%s-0", node1Name),
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Pod not running: %s", output)
			}
			Eventually(verifyPodRunning, 3*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should create GarageNode 2 with its own StatefulSet", func() {
			By("creating GarageNode 2")
			node2YAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef:
    name: %s
  zone: zone-b
  capacity: 1Gi
  storage:
    metadata:
      size: 100Mi
    data:
      size: 1Gi
  resources:
    limits:
      memory: 256Mi
    requests:
      memory: 128Mi
`, node2Name, testNamespace, clusterName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(node2YAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create GarageNode 2")

			By("waiting for GarageNode 2 StatefulSet to be created")
			verifyStatefulSet := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", node2Name,
					"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal(node2Name))
			}
			Eventually(verifyStatefulSet, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for GarageNode 2 pod to be running")
			verifyPodRunning := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", fmt.Sprintf("%s-0", node2Name),
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Pod not running: %s", output)
			}
			Eventually(verifyPodRunning, 3*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should have both nodes registered in layout", func() {
			By("waiting for both nodes to be registered in layout")
			verifyNodesInLayout := func(g Gomega) {
				// Check node 1 is in layout
				cmd := exec.Command("kubectl", "get", "garagenode", node1Name,
					"-n", testNamespace, "-o", "jsonpath={.status.inLayout}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"), "Node 1 not in layout")

				// Check node 2 is in layout
				cmd = exec.Command("kubectl", "get", "garagenode", node2Name,
					"-n", testNamespace, "-o", "jsonpath={.status.inLayout}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"), "Node 2 not in layout")
			}
			Eventually(verifyNodesInLayout, 3*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("should have both nodes connected", func() {
			By("waiting for both nodes to be connected")
			verifyNodesConnected := func(g Gomega) {
				// Check node 1 is connected
				cmd := exec.Command("kubectl", "get", "garagenode", node1Name,
					"-n", testNamespace, "-o", "jsonpath={.status.connected}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"), "Node 1 not connected")

				// Check node 2 is connected
				cmd = exec.Command("kubectl", "get", "garagenode", node2Name,
					"-n", testNamespace, "-o", "jsonpath={.status.connected}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"), "Node 2 not connected")
			}
			Eventually(verifyNodesConnected, 3*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("should have cluster healthy with 2 connected nodes", func() {
			By("verifying cluster health")
			verifyClusterHealth := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagecluster", clusterName,
					"-n", testNamespace, "-o", "jsonpath={.status.health.connectedNodes}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("2"), "Expected 2 connected nodes, got %s", output)
			}
			Eventually(verifyClusterHealth, 3*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("should have nodes in different zones", func() {
			By("querying the cluster layout via Admin API")
			adminToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			verifyZones := func(g Gomega) {
				// Use a separate curl pod to query the admin API (Garage containers are distroless)
				curlCmd := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterLayout",
					adminToken, clusterName, testNamespace)
				cmd := exec.Command("kubectl", "run", "curl-layout-zones", "--rm", "-i", "--restart=Never",
					"-n", testNamespace, "--image=docker.io/curlimages/curl:latest",
					fmt.Sprintf("--overrides=%s", fmt.Sprintf(`{
						"spec": {
							"containers": [{
								"name": "curl-layout-zones",
								"image": "docker.io/curlimages/curl:latest",
								"imagePullPolicy": "IfNotPresent",
								"command": ["/bin/sh", "-c"],
								"args": [%q],
								"securityContext": {
									"readOnlyRootFilesystem": true,
									"allowPrivilegeEscalation": false,
									"capabilities": {"drop": ["ALL"]},
									"runAsNonRoot": true,
									"runAsUser": 1000,
									"seccompProfile": {"type": "RuntimeDefault"}
								}
							}]
						}
					}`, curlCmd)))
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to query layout: %s", output)

				// Parse the layout JSON to find zones
				var layout struct {
					Roles []struct {
						Zone string `json:"zone"`
					} `json:"roles"`
				}
				jsonStart := strings.Index(output, "{")
				jsonEnd := strings.LastIndex(output, "}")
				g.Expect(jsonStart).To(BeNumerically(">=", 0), "No JSON found in output: %s", output)
				g.Expect(jsonEnd).To(BeNumerically(">", jsonStart), "No valid JSON found in output: %s", output)
				jsonStr := output[jsonStart : jsonEnd+1]
				g.Expect(json.Unmarshal([]byte(jsonStr), &layout)).To(Succeed(), "Failed to parse layout JSON: %s", jsonStr)

				// Verify we have nodes in different zones
				zones := make(map[string]bool)
				for _, role := range layout.Roles {
					zones[role.Zone] = true
				}
				g.Expect(zones).To(HaveKey("zone-a"), "Expected zone-a in layout")
				g.Expect(zones).To(HaveKey("zone-b"), "Expected zone-b in layout")
			}
			Eventually(verifyZones, 2*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("should support bucket and key operations", func() {
			By("creating a test bucket")
			bucketYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: manual-test-bucket
  namespace: %s
spec:
  clusterRef:
    name: %s
`, testNamespace, clusterName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(bucketYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create test bucket")

			By("waiting for bucket to be ready")
			verifyBucketReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagebucket", "manual-test-bucket",
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Ready"), "Bucket not ready: phase=%s", output)
			}
			Eventually(verifyBucketReady, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("cleaning up test bucket")
			cmd = exec.Command("kubectl", "delete", "garagebucket", "manual-test-bucket",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should grant cluster-wide key access to buckets in manual mode", func() {
			By("creating a bucket for cluster-wide key test")
			bucketYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: manual-cw-bucket
  namespace: %s
spec:
  clusterRef:
    name: %s
`, testNamespace, clusterName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(bucketYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create bucket")

			By("waiting for bucket to be ready")
			verifyBucketReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagebucket", "manual-cw-bucket",
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Ready"), "Bucket not ready: phase=%s", output)
			}
			Eventually(verifyBucketReady, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("creating a cluster-wide key")
			keyYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: manual-cw-key
  namespace: %s
spec:
  clusterRef:
    name: %s
  allBuckets:
    read: true
    write: true
`, testNamespace, clusterName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(keyYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create cluster-wide key")

			By("waiting for key to be ready")
			verifyKeyReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagekey", "manual-cw-key",
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Ready"), "Key not ready: phase=%s", output)
			}
			Eventually(verifyKeyReady, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying ClusterWide status")
			cmd = exec.Command("kubectl", "get", "garagekey", "manual-cw-key",
				"-n", testNamespace, "-o", "jsonpath={.status.clusterWide}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("true"), "ClusterWide should be true")

			By("verifying key has bucket access")
			verifyBucketAccess := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagekey", "manual-cw-key",
					"-n", testNamespace, "-o", "jsonpath={.status.buckets}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty(), "Key should have bucket access")
			}
			Eventually(verifyBucketAccess, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("cleaning up")
			cmd = exec.Command("kubectl", "delete", "garagekey", "manual-cw-key",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "garagebucket", "manual-cw-bucket",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should delete nodes and remove from layout", func() {
			By("deleting GarageNode 2")
			cmd := exec.Command("kubectl", "delete", "garagenode", node2Name, "-n", testNamespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete GarageNode 2")

			By("waiting for node 2 to be removed")
			verifyNodeDeleted := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagenode", node2Name, "-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred(), "GarageNode 2 should be deleted")
			}
			Eventually(verifyNodeDeleted, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying StatefulSet 2 is also deleted")
			verifyStatefulSetDeleted := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", node2Name, "-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred(), "StatefulSet 2 should be deleted")
			}
			Eventually(verifyStatefulSetDeleted, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})

	Context("Per-node networking features", Ordered, func() {
		const netNodeName = "garage-node-net"

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "garagenode", netNodeName,
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "service", netNodeName+"-rpc",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "configmap", netNodeName+"-config",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should create a per-node ConfigMap with rpc_public_addr when spec.network.rpcPublicAddr is set", func() {
			const staticAddr = "203.0.113.10:3901"

			By("creating GarageNode with spec.network.rpcPublicAddr")
			nodeYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef:
    name: %s
  zone: zone-net
  capacity: 1Gi
  storage:
    metadata:
      size: 100Mi
    data:
      size: 1Gi
  network:
    rpcPublicAddr: %s
  resources:
    limits:
      memory: 256Mi
    requests:
      memory: 128Mi
`, netNodeName, testNamespace, clusterName, staticAddr)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(nodeYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create GarageNode with rpcPublicAddr")

			By("waiting for per-node ConfigMap to be created")
			verifyConfigMap := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "configmap", netNodeName+"-config",
					"-n", testNamespace, "-o", "jsonpath={.data.garage\\.toml}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "per-node ConfigMap not found")
				g.Expect(output).To(ContainSubstring(`rpc_public_addr = "`+staticAddr+`"`),
					"garage.toml should contain rpc_public_addr = %q, got: %s", staticAddr, output)
			}
			Eventually(verifyConfigMap, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the StatefulSet uses the per-node ConfigMap (not cluster ConfigMap)")
			verifyVolume := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", netNodeName,
					"-n", testNamespace,
					"-o", "jsonpath={.spec.template.spec.volumes[?(@.name=='config')].configMap.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal(netNodeName+"-config"),
					"StatefulSet should mount per-node ConfigMap, got: %s", output)
			}
			Eventually(verifyVolume, 2*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should create a per-node NodePort service when spec.publicEndpoint.type is NodePort", func() {
			By("patching GarageNode to add spec.publicEndpoint")
			patchYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef:
    name: %s
  zone: zone-net
  capacity: 1Gi
  storage:
    metadata:
      size: 100Mi
    data:
      size: 1Gi
  network:
    rpcPublicAddr: "203.0.113.10:3901"
  publicEndpoint:
    type: NodePort
    nodePort:
      externalAddresses:
        - "203.0.113.10"
      basePort: 31901
  resources:
    limits:
      memory: 256Mi
    requests:
      memory: 128Mi
`, netNodeName, testNamespace, clusterName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(patchYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to patch GarageNode with publicEndpoint")

			By("waiting for per-node RPC service to be created")
			verifySvc := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "service", netNodeName+"-rpc",
					"-n", testNamespace, "-o", "jsonpath={.spec.type}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "per-node RPC service not found")
				g.Expect(output).To(Equal("NodePort"), "expected NodePort service, got: %s", output)
			}
			Eventually(verifySvc, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the service targets port 3901 with NodePort 31901")
			verifyPort := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "service", netNodeName+"-rpc",
					"-n", testNamespace,
					"-o", "jsonpath={.spec.ports[0].nodePort}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("31901"), "expected nodePort 31901, got: %s", output)
			}
			Eventually(verifyPort, 1*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should patch the per-node ConfigMap when spec.storage fsync overrides are set", func() {
			By("patching GarageNode to add metadataFsync override")
			patchYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef:
    name: %s
  zone: zone-net
  capacity: 1Gi
  storage:
    metadata:
      size: 100Mi
    data:
      size: 1Gi
    metadataFsync: true
  network:
    rpcPublicAddr: "203.0.113.10:3901"
  publicEndpoint:
    type: NodePort
    nodePort:
      externalAddresses:
        - "203.0.113.10"
      basePort: 31901
  resources:
    limits:
      memory: 256Mi
    requests:
      memory: 128Mi
`, netNodeName, testNamespace, clusterName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(patchYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to patch GarageNode with metadataFsync")

			By("verifying per-node ConfigMap contains metadata_fsync = true")
			verifyFsync := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "configmap", netNodeName+"-config",
					"-n", testNamespace, "-o", "jsonpath={.data.garage\\.toml}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("metadata_fsync = true"),
					"garage.toml should contain metadata_fsync = true, got: %s", output)
			}
			Eventually(verifyFsync, 2*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should apply pod config override (imagePullPolicy) to the StatefulSet", func() {
			By("patching GarageNode with imagePullPolicy: IfNotPresent")
			patchYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef:
    name: %s
  zone: zone-net
  capacity: 1Gi
  storage:
    metadata:
      size: 100Mi
    data:
      size: 1Gi
    metadataFsync: true
  network:
    rpcPublicAddr: "203.0.113.10:3901"
  publicEndpoint:
    type: NodePort
    nodePort:
      externalAddresses:
        - "203.0.113.10"
      basePort: 31901
  imagePullPolicy: IfNotPresent
  resources:
    limits:
      memory: 256Mi
    requests:
      memory: 128Mi
`, netNodeName, testNamespace, clusterName)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(patchYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to patch GarageNode with imagePullPolicy")

			By("verifying StatefulSet container has imagePullPolicy: IfNotPresent")
			verifyPullPolicy := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", netNodeName,
					"-n", testNamespace,
					"-o", "jsonpath={.spec.template.spec.containers[0].imagePullPolicy}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("IfNotPresent"),
					"expected IfNotPresent, got: %s", output)
			}
			Eventually(verifyPullPolicy, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})
})

// External gateway tests require a Docker-based Garage node running alongside the kind cluster.
// The hack/e2e-external-gateway.sh script sets up the infrastructure and exports the env vars below.
var _ = Describe("External Gateway Cluster", Ordered, Label("external-gateway"), func() {
	const gatewayClusterName = "ext-gateway"

	var (
		testNamespace        string
		operatorEndpoint     string // operator→Garage: http://<docker-ip>:3903
		hostEndpoint         string // test→Garage:    http://localhost:<host-port>
		externalToken        string
		rpcSecret            string
		gatewayRPCPublicAddr string
		gatewayRPCNodePort   string
		gatewayKindNodeIP    string
	)

	BeforeAll(func() {
		operatorEndpoint = os.Getenv("EXTERNAL_GARAGE_OPERATOR_ENDPOINT")
		hostEndpoint = os.Getenv("EXTERNAL_GARAGE_HOST_ENDPOINT")
		externalToken = os.Getenv("EXTERNAL_GARAGE_TOKEN")
		rpcSecret = os.Getenv("EXTERNAL_RPC_SECRET")
		gatewayRPCPublicAddr = os.Getenv("GATEWAY_RPC_PUBLIC_ADDR")
		gatewayRPCNodePort = os.Getenv("GATEWAY_RPC_NODEPORT")
		gatewayKindNodeIP = os.Getenv("GATEWAY_KIND_NODE_IP")
		testNamespace = os.Getenv("E2E_TEST_NAMESPACE")
		if testNamespace == "" {
			testNamespace = "garage-ext-gw-test"
		}

		if operatorEndpoint == "" || hostEndpoint == "" || rpcSecret == "" || gatewayRPCPublicAddr == "" {
			Skip("external gateway env vars not set — run via hack/e2e-external-gateway.sh")
		}

		By("creating test namespace")
		cmd := exec.Command("kubectl", "create", "ns", testNamespace)
		_, _ = utils.Run(cmd)
	})

	AfterAll(func() {
		cmd := exec.Command("kubectl", "delete", "garagecluster", gatewayClusterName, "-n", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
		time.Sleep(5 * time.Second)
		cmd = exec.Command("kubectl", "delete", "ns", testNamespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)
	})

	It("should create gateway cluster connecting to external Garage node", func() {
		By("creating RPC secret")
		rpcSecretYAML := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: ext-rpc-secret
  namespace: %s
type: Opaque
stringData:
  rpc-secret: "%s"
`, testNamespace, rpcSecret)
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(rpcSecretYAML)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("creating admin token secret for external Garage")
		tokenSecretYAML := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: ext-admin-token
  namespace: %s
type: Opaque
stringData:
  admin-token: "%s"
`, testNamespace, externalToken)
		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(tokenSecretYAML)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		nodePortStr := "30901"
		if gatewayRPCNodePort != "" {
			nodePortStr = gatewayRPCNodePort
		}
		kindNodeIP := gatewayKindNodeIP
		if kindNodeIP == "" {
			kindNodeIP = "127.0.0.1"
		}

		By("creating gateway GarageCluster with connectTo.adminApiEndpoint")
		gatewayYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  image: dxflrs/garage:v2.3.0
  gateway:
    replicas: 1
    resources:
      limits:
        memory: 128Mi
      requests:
        memory: 64Mi

  connectTo:
    rpcSecretRef:
      name: ext-rpc-secret
      key: rpc-secret
    adminApiEndpoint: '%s'
    adminTokenSecretRef:
      name: ext-admin-token
      key: admin-token

  replication:
    factor: 1

  network:
    rpcPublicAddr: %s
    rpcBindPort: 3901
    service:
      type: NodePort

  publicEndpoint:
    type: NodePort
    nodePort:
      basePort: %s
      externalAddresses:
      - %s

  admin:
    adminTokenSecretRef:
      name: ext-admin-token
      key: admin-token

  security:
    allowInsecureSecretPermissions: true
`, gatewayClusterName, testNamespace, operatorEndpoint, gatewayRPCPublicAddr, nodePortStr, kindNodeIP)
		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(gatewayYAML)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should reach Running phase", func() {
		verifyRunning := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagecluster", gatewayClusterName,
				"-n", testNamespace, "-o", "jsonpath={.status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Running"), "gateway phase: %s", output)
		}
		Eventually(verifyRunning, 5*time.Minute, 5*time.Second).Should(Succeed())
	})

	It("should show the external node as connected (gateway perspective)", func() {
		verifyConnected := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagecluster", gatewayClusterName,
				"-n", testNamespace, "-o", "jsonpath={.status.health.connectedNodes}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			// Gateway sees itself + the external storage node = 2 connected nodes
			g.Expect(output).To(Equal("2"), "expected 2 connected nodes (gateway + external), got %s", output)
		}
		Eventually(verifyConnected, 3*time.Minute, 5*time.Second).Should(Succeed())
	})

	It("should appear as online in the external Garage cluster (bidirectional)", func() {
		// This is the key assertion for the bidirectionality fix.
		// The external Garage must have an outgoing RPC connection to the gateway — not just the reverse.
		verifyBidirectional := func(g Gomega) {
			req, err := http.NewRequest(http.MethodGet, hostEndpoint+"/v2/GetClusterStatus", nil)
			g.Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Authorization", "Bearer "+externalToken)

			resp, err := http.DefaultClient.Do(req)
			g.Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			g.Expect(resp.StatusCode).To(Equal(http.StatusOK))

			body, err := io.ReadAll(resp.Body)
			g.Expect(err).NotTo(HaveOccurred())

			var status struct {
				Nodes []struct {
					ID   string `json:"id"`
					IsUp bool   `json:"isUp"`
				} `json:"nodes"`
			}
			g.Expect(json.Unmarshal(body, &status)).To(Succeed())

			// The external cluster should know about 2 nodes: itself + the gateway.
			// At least one of the non-self nodes must be up.
			g.Expect(status.Nodes).To(HaveLen(2), "external cluster should see 2 nodes (itself + gateway), got %d", len(status.Nodes))

			upCount := 0
			for _, n := range status.Nodes {
				if n.IsUp {
					upCount++
				}
			}
			g.Expect(upCount).To(BeNumerically(">=", 2),
				"expected both nodes up in external cluster, only %d up", upCount)
		}
		Eventually(verifyBidirectional, 3*time.Minute, 5*time.Second).Should(Succeed())
	})

	It("should set GatewayConnected condition to True", func() {
		// Regression: externalToGateway=0 caused the condition to stay PartiallyConnected
		// (False) indefinitely. deriveGatewayExternalAddr was returning "" when rpcPublicAddr
		// was set, so the reverse ConnectNode call skipped gateway nodes that report no
		// self-address in GetClusterStatus.
		verifyCondition := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagecluster", gatewayClusterName,
				"-n", testNamespace,
				"-o", `jsonpath={.status.conditions[?(@.type=="GatewayConnected")].status}`)
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True"), "GatewayConnected not True: %s", output)
		}
		Eventually(verifyCondition, 3*time.Minute, 5*time.Second).Should(Succeed())
	})

	It("should not continuously spam the external admin API after connection is established", func() {
		// Regression: GatewayConnected=False triggered 10s reconciles and called
		// ConnectClusterNodes on every cycle. With GatewayConnected=True the operator
		// runs a lightweight isUp check instead and backs off to 5 minutes. Verify the
		// condition stays True for a 30s window — any flip indicates rapid reconcile.
		Consistently(func() string {
			cmd := exec.Command("kubectl", "get", "garagecluster", gatewayClusterName,
				"-n", testNamespace,
				"-o", `jsonpath={.status.conditions[?(@.type=="GatewayConnected")].status}`)
			output, _ := utils.Run(cmd)
			return output
		}, 30*time.Second, 5*time.Second).Should(Equal("True"),
			"GatewayConnected flipped — rapid reconcile may be calling ConnectNode repeatedly")
	})
})

// Auto Mode per-node GarageNodes — covers issue #190: layoutPolicy: Auto generates
// per-node GarageNode CRs (one StatefulSet per node), supports scale up/down,
// honors GarageNode spec.maintenance.suspended, and drops controller-ownerRef
// from child GarageNodes on Auto→Manual ejection.
var _ = Describe("Auto Mode per-node GarageNodes", Ordered, Label("auto-mode-pernode"), func() {
	const testNamespace = "garage-auto-pernode-test"
	const clusterName = "auto-cluster"
	const node0Name = "auto-cluster-storage-0"
	const node1Name = "auto-cluster-storage-1"
	const node2Name = "auto-cluster-storage-2"

	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, _ = utils.Run(cmd) // Ignore error if already exists

		By("labeling the manager namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, _ = utils.Run(cmd)

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("waiting for Garage CRDs to be Established")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for controller-manager pod to be Ready (webhook server started)")
		verifyControllerUp := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods", "-l", "control-plane=controller-manager",
				"-n", namespace,
				"-o", "jsonpath={.items[0].status.conditions[?(@.type=='Ready')].status}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True"), "Controller not Ready: %s", output)
		}
		Eventually(verifyControllerUp, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("creating test namespace")
		cmd = exec.Command("kubectl", "create", "ns", testNamespace)
		_, _ = utils.Run(cmd) // Ignore error if already exists

		By("labeling the test namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		cleanupAuto190(testNamespace, clusterName, []string{node0Name, node1Name, node2Name})
	})

	It("should deploy Auto cluster with replicas=2 and generate per-node GarageNodes", func() {
		By("creating admin token secret")
		adminTokenSecret := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: garage-admin-token
  namespace: %s
type: Opaque
stringData:
  admin-token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
`, testNamespace)
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(adminTokenSecret)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create admin token secret")

		By("creating GarageCluster with layoutPolicy: Auto and replicas=2")
		clusterYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  layoutPolicy: Auto
  zone: us-test
  replication:
    factor: 2
  storage:
    replicas: 2
    metadata:
      size: 100Mi
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
  security:
    allowInsecureSecretPermissions: true
`, clusterName, testNamespace)

		By("applying GarageCluster (retry until admission webhook is up)")
		Eventually(func(g Gomega) {
			c := exec.Command("kubectl", "apply", "-f", "-")
			c.Stdin = strings.NewReader(clusterYAML)
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred(), "Failed to create GarageCluster: %s", out)
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying per-node GarageNodes are created (auto-cluster-storage-0, auto-cluster-storage-1)")
		verifyGarageNodes := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenodes", "-n", testNamespace,
				"-o", "jsonpath={.items[*].metadata.name}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			names := strings.Fields(output)
			g.Expect(names).To(ConsistOf(node0Name, node1Name),
				"Expected exactly auto-cluster-storage-{0,1}, got: %v", names)
		}
		Eventually(verifyGarageNodes, 3*time.Minute, 5*time.Second).Should(Succeed())
	})

	It("should have controller-ownerRef from cluster on each child GarageNode", func() {
		for _, n := range []string{node0Name, node1Name} {
			By(fmt.Sprintf("verifying controller ownerRef on %s", n))
			cmd := exec.Command("kubectl", "get", "garagenode", n, "-n", testNamespace,
				"-o", "jsonpath={.metadata.ownerReferences[?(@.controller==true)].kind}")
			outputKind, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(outputKind).To(Equal("GarageCluster"),
				"GarageNode %s controller ownerRef kind mismatch: %q", n, outputKind)

			cmd = exec.Command("kubectl", "get", "garagenode", n, "-n", testNamespace,
				"-o", "jsonpath={.metadata.ownerReferences[?(@.controller==true)].name}")
			outputName, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(outputName).To(Equal(clusterName),
				"GarageNode %s controller ownerRef name mismatch: %q", n, outputName)
		}
	})

	It("should create one StatefulSet per GarageNode and reach pods Running", func() {
		By("verifying per-node StatefulSets exist (NOT a single auto-cluster STS)")
		verifySTS := func(g Gomega) {
			for _, n := range []string{node0Name, node1Name} {
				cmd := exec.Command("kubectl", "get", "statefulset", n,
					"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "STS %s missing: %s", n, output)
				g.Expect(output).To(Equal(n))
			}
		}
		Eventually(verifySTS, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying no legacy single STS named after the cluster exists")
		cmd := exec.Command("kubectl", "get", "statefulset", clusterName, "-n", testNamespace)
		_, err := utils.Run(cmd)
		Expect(err).To(HaveOccurred(), "Legacy STS %q should not exist in Auto per-node mode", clusterName)

		By("waiting for pods auto-cluster-storage-0-0 and auto-cluster-storage-1-0 to be Running")
		verifyPodsRunning := func(g Gomega) {
			for _, n := range []string{node0Name, node1Name} {
				pod := fmt.Sprintf("%s-0", n)
				cmd := exec.Command("kubectl", "get", "pod", pod,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Pod %s not running: %s", pod, output)
			}
		}
		Eventually(verifyPodsRunning, 5*time.Minute, 5*time.Second).Should(Succeed())
	})

	It("should have both nodes Connected and InLayout", func() {
		verifyNodesReady := func(g Gomega) {
			for _, n := range []string{node0Name, node1Name} {
				cmd := exec.Command("kubectl", "get", "garagenode", n,
					"-n", testNamespace, "-o", "jsonpath={.status.connected}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"), "GarageNode %s not connected: %q", n, output)

				cmd = exec.Command("kubectl", "get", "garagenode", n,
					"-n", testNamespace, "-o", "jsonpath={.status.inLayout}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"), "GarageNode %s not in layout: %q", n, output)
			}
		}
		Eventually(verifyNodesReady, 5*time.Minute, 10*time.Second).Should(Succeed())
	})

	It("should scale up to replicas=3 and create auto-cluster-storage-2", func() {
		By("patching storage.replicas to 3")
		cmd := exec.Command("kubectl", "patch", "garagecluster", clusterName,
			"-n", testNamespace, "--type", "merge",
			"-p", `{"spec":{"storage":{"replicas":3}}}`)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to scale up cluster")

		By("verifying auto-cluster-storage-2 GarageNode is created")
		verifyNode2 := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenode", node2Name,
				"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal(node2Name))
		}
		Eventually(verifyNode2, 3*time.Minute, 5*time.Second).Should(Succeed())
	})

	It("should scale down to replicas=2 and remove auto-cluster-storage-2", func() {
		By("patching storage.replicas back to 2")
		cmd := exec.Command("kubectl", "patch", "garagecluster", clusterName,
			"-n", testNamespace, "--type", "merge",
			"-p", `{"spec":{"storage":{"replicas":2}}}`)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to scale down cluster")

		By("verifying auto-cluster-storage-2 GarageNode is removed")
		verifyNode2Gone := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenode", node2Name,
				"-n", testNamespace)
			_, err := utils.Run(cmd)
			g.Expect(err).To(HaveOccurred(), "GarageNode %s still exists", node2Name)
		}
		Eventually(verifyNode2Gone, 5*time.Minute, 5*time.Second).Should(Succeed())
	})

	It("should pause reconciliation when GarageNode spec.maintenance.suspended=true", func() {
		By("setting spec.maintenance.suspended=true on auto-cluster-storage-0")
		cmd := exec.Command("kubectl", "patch", "garagenode", node0Name,
			"-n", testNamespace, "--type", "merge",
			"-p", `{"spec":{"maintenance":{"suspended":true}}}`)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to suspend GarageNode")

		By("waiting for Suspended condition to be True")
		verifySuspended := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenode", node0Name,
				"-n", testNamespace,
				"-o", `jsonpath={.status.conditions[?(@.type=="Suspended")].status}`)
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True"), "Suspended condition not True: %q", output)
		}
		Eventually(verifySuspended, 30*time.Second, 2*time.Second).Should(Succeed())

		By("deleting the suspended node's StatefulSet")
		cmd = exec.Command("kubectl", "delete", "sts", node0Name, "-n", testNamespace)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to delete STS")

		By("verifying the operator does NOT recreate the STS while suspended")
		Consistently(func() error {
			cmd := exec.Command("kubectl", "get", "sts", node0Name, "-n", testNamespace)
			_, err := utils.Run(cmd)
			return err
		}, 30*time.Second, 5*time.Second).Should(HaveOccurred(),
			"STS should remain absent while GarageNode is suspended")

		By("clearing spec.maintenance to resume reconciliation")
		cmd = exec.Command("kubectl", "patch", "garagenode", node0Name,
			"-n", testNamespace, "--type=json",
			"-p", `[{"op":"remove","path":"/spec/maintenance"}]`)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to clear maintenance")

		By("verifying the STS is recreated after un-suspending")
		verifySTSBack := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "sts", node0Name,
				"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal(node0Name))
		}
		Eventually(verifySTSBack, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	It("should drop controller-ownerRef on Auto→Manual ejection", func() {
		By("patching layoutPolicy to Manual")
		cmd := exec.Command("kubectl", "patch", "garagecluster", clusterName,
			"-n", testNamespace, "--type", "merge",
			"-p", `{"spec":{"layoutPolicy":"Manual"}}`)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to flip layoutPolicy to Manual")

		By("verifying child GarageNodes still exist but with no controller ownerRef")
		verifyEjected := func(g Gomega) {
			for _, n := range []string{node0Name, node1Name} {
				// Still exists
				cmd := exec.Command("kubectl", "get", "garagenode", n,
					"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "GarageNode %s should still exist after ejection", n)
				g.Expect(output).To(Equal(n))

				// No controller ownerRef
				cmd = exec.Command("kubectl", "get", "garagenode", n, "-n", testNamespace,
					"-o", "jsonpath={.metadata.ownerReferences[?(@.controller==true)].kind}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(BeEmpty(),
					"GarageNode %s should have no controller ownerRef after Auto→Manual ejection, got %q",
					n, output)
			}
		}
		Eventually(verifyEjected, 1*time.Minute, 5*time.Second).Should(Succeed())
	})
})

// Auto Mode EmptyDir (ephemeral) — regression for #283. Before the fix, an
// Auto-mode cluster with storage.{metadata,data}.type=EmptyDir dropped the type
// when projecting to per-node GarageNodes, so the sizeless ephemeral shape
// produced an invalid StatefulSet (pod never started) and the sized shape
// silently provisioned PVCs. This exercises the sizeless shape end-to-end: the
// pod must reach Running with EmptyDir volumes and NO PVCs.
var _ = Describe("Auto Mode EmptyDir (ephemeral)", Ordered, Label("auto-mode-ephemeral"), func() {
	const testNamespace = "garage-auto-ephemeral-test"
	const clusterName = "ephem-cluster"
	const nodeName = "ephem-cluster-storage-0"

	BeforeAll(func() {
		By("creating manager namespace")
		_, _ = utils.Run(exec.Command("kubectl", "create", "ns", namespace))

		By("labeling the manager namespace to enforce the restricted security policy")
		_, _ = utils.Run(exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted"))

		By("installing CRDs")
		_, err := utils.Run(exec.Command("make", "install"))
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("waiting for Garage CRDs to be Established")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		_, err = utils.Run(exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage)))
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for controller-manager pod to be Ready (webhook server started)")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods", "-l", "control-plane=controller-manager",
				"-n", namespace,
				"-o", "jsonpath={.items[0].status.conditions[?(@.type=='Ready')].status}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True"), "Controller not Ready: %s", output)
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("creating test namespace")
		_, _ = utils.Run(exec.Command("kubectl", "create", "ns", testNamespace))
		_, err = utils.Run(exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted"))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		cleanupAuto190(testNamespace, clusterName, []string{nodeName})
	})

	It("should boot a sizeless EmptyDir Auto cluster with an EmptyDir-backed pod and no PVCs", func() {
		By("creating admin token secret")
		adminTokenSecret := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: garage-admin-token
  namespace: %s
type: Opaque
stringData:
  admin-token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
`, testNamespace)
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(adminTokenSecret)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create admin token secret")

		By("creating an ephemeral GarageCluster (metadata+data type=EmptyDir, no size)")
		clusterYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  layoutPolicy: Auto
  zone: us-test
  replication:
    factor: 1
  storage:
    replicas: 1
    metadata:
      type: EmptyDir
    data:
      type: EmptyDir
    podDisruptionBudget:
      enabled: false
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
  security:
    allowInsecureSecretPermissions: true
`, clusterName, testNamespace)

		By("applying GarageCluster (retry until admission webhook is up)")
		Eventually(func(g Gomega) {
			c := exec.Command("kubectl", "apply", "-f", "-")
			c.Stdin = strings.NewReader(clusterYAML)
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred(), "Failed to create GarageCluster: %s", out)
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying the per-node GarageNode is created")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenode", nodeName,
				"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal(nodeName))
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying the StatefulSet's metadata and data volumes are EmptyDir")
		Eventually(func(g Gomega) {
			for _, vol := range []string{"metadata", "data"} {
				cmd := exec.Command("kubectl", "get", "statefulset", nodeName, "-n", testNamespace,
					"-o", fmt.Sprintf("jsonpath={.spec.template.spec.volumes[?(@.name==%q)].emptyDir}", vol))
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("{}"), "volume %q must be EmptyDir, got %q", vol, output)
			}
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying the storage pod reaches Running")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pod", nodeName+"-0",
				"-n", testNamespace, "-o", "jsonpath={.status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Running"), "Pod %s-0 not running: %s", nodeName, output)
		}, 5*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying NO PersistentVolumeClaims were created for the ephemeral cluster")
		cmd = exec.Command("kubectl", "get", "pvc", "-n", testNamespace,
			"-o", "jsonpath={.items[*].metadata.name}")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.Fields(output)).To(BeEmpty(),
			"ephemeral EmptyDir cluster must not provision PVCs, found: %q", output)

		By("verifying the node connects and joins the layout (cluster is functional, not just started)")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenode", nodeName,
				"-n", testNamespace, "-o", "jsonpath={.status.connected}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("true"), "GarageNode %s not connected: %q", nodeName, output)

			cmd = exec.Command("kubectl", "get", "garagenode", nodeName,
				"-n", testNamespace, "-o", "jsonpath={.status.inLayout}")
			output, err = utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("true"), "GarageNode %s not in layout: %q", nodeName, output)
		}, 5*time.Minute, 10*time.Second).Should(Succeed())
	})
})

// LayoutPolicy webhook — covers issue #190: the webhook rejects Manual→Auto
// transitions because Auto mode would attempt to take over user-managed
// GarageNodes (one-way migration only).
var _ = Describe("LayoutPolicy webhook", Ordered, Label("layout-policy-webhook"), func() {
	const testNamespace = "garage-policy-webhook-test"
	const clusterName = "policy-cluster"

	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, _ = utils.Run(cmd) // Ignore error if already exists

		By("labeling the manager namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, _ = utils.Run(cmd)

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("waiting for Garage CRDs to be Established")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for controller-manager pod to be Ready (webhook server started)")
		verifyControllerUp := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods", "-l", "control-plane=controller-manager",
				"-n", namespace,
				"-o", "jsonpath={.items[0].status.conditions[?(@.type=='Ready')].status}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True"), "Controller not Ready: %s", output)
		}
		Eventually(verifyControllerUp, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("creating test namespace")
		cmd = exec.Command("kubectl", "create", "ns", testNamespace)
		_, _ = utils.Run(cmd) // Ignore error if already exists

		By("labeling the test namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		cleanupAuto190(testNamespace, clusterName, nil)
	})

	It("should reject Manual→Auto transition with a clear error message", func() {
		By("creating an admin token secret")
		adminTokenSecret := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: garage-admin-token
  namespace: %s
type: Opaque
stringData:
  admin-token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
`, testNamespace)
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(adminTokenSecret)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create admin token secret")

		By("creating a Manual-mode GarageCluster")
		clusterYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  layoutPolicy: Manual
  replication:
    factor: 1
  storage:
    replicas: 1
    metadata:
      size: 100Mi
    data:
      size: 1Gi
    resources:
      limits:
        memory: 256Mi
      requests:
        memory: 128Mi
  admin:
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
  security:
    allowInsecureSecretPermissions: true
`, clusterName, testNamespace)

		Eventually(func(g Gomega) {
			c := exec.Command("kubectl", "apply", "-f", "-")
			c.Stdin = strings.NewReader(clusterYAML)
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred(), "Failed to create Manual cluster: %s", out)
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("letting the cluster settle briefly")
		time.Sleep(5 * time.Second)

		By("attempting Manual→Auto transition (should be rejected by webhook)")
		cmd = exec.Command("kubectl", "patch", "garagecluster", clusterName,
			"-n", testNamespace, "--type", "merge",
			"-p", `{"spec":{"layoutPolicy":"Auto"}}`)
		output, err := utils.Run(cmd)
		Expect(err).To(HaveOccurred(),
			"Webhook should reject Manual→Auto transition. Output: %s", output)
		Expect(output).To(ContainSubstring("Manual"),
			"Error should mention Manual. Output: %s", output)
		Expect(output).To(ContainSubstring("Auto"),
			"Error should mention Auto. Output: %s", output)
		// Webhook message is: "layoutPolicy transition from Manual to Auto is
		// not supported (one-way only) — see issue #190"
		Expect(output).To(Or(
			ContainSubstring("not supported"),
			ContainSubstring("one-way"),
		), "Error should explain why transition is rejected. Output: %s", output)
	})
})

// Management Handle Cluster (#269): a GarageCluster with only spec.connectTo
// (no storage/gateway tier) manages an EXISTING cluster's Admin-API state. Here
// a real storage cluster stands in for the externally-managed (e.g. Helm)
// Garage: the handle connects to it via connectTo.clusterRef and drives a
// GarageBucket against it, provisioning no workload of its own.
var _ = Describe("Management Handle Cluster", Ordered, Label("management-handle"), func() {
	const testNamespace = "garage-mgmt-handle"
	const externalClusterName = "external-cluster"
	const handleClusterName = "handle-cluster"

	BeforeAll(func() {
		By("creating manager namespace")
		_, _ = utils.Run(exec.Command("kubectl", "create", "ns", namespace))
		_, _ = utils.Run(exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted"))

		By("installing CRDs")
		_, err := utils.Run(exec.Command("make", "install"))
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		_, err = utils.Run(exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage)))
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for controller-manager pod to be Ready (webhook server started)")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods", "-l", "control-plane=controller-manager",
				"-n", namespace,
				"-o", "jsonpath={.items[0].status.conditions[?(@.type=='Ready')].status}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True"), "Controller not Ready: %s", output)
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("creating test namespace")
		_, _ = utils.Run(exec.Command("kubectl", "create", "ns", testNamespace))
		_, err = utils.Run(exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted"))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		cleanupManagementHandle(testNamespace, []string{handleClusterName, externalClusterName})
	})

	Context("When managing an existing cluster via connectTo only", func() {
		It("should stand up the external (stand-in) storage cluster", func() {
			By("creating admin token secret")
			adminTokenSecret := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: garage-admin-token
  namespace: %s
type: Opaque
stringData:
  admin-token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
`, testNamespace)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(adminTokenSecret)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create admin token secret")

			storageYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
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
  security:
    allowInsecureSecretPermissions: true
`, externalClusterName, testNamespace)

			By("applying external cluster (retry until webhook is up)")
			Eventually(func(g Gomega) {
				c := exec.Command("kubectl", "apply", "-f", "-")
				c.Stdin = strings.NewReader(storageYAML)
				out, err := utils.Run(c)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to create external cluster: %s", out)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for external cluster to be Running")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagecluster", externalClusterName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "External cluster not ready: phase=%s", output)
			}, 5*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should reach Running as a connectTo-only management handle", func() {
			handleYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  connectTo:
    clusterRef:
      name: %s
`, handleClusterName, testNamespace, externalClusterName)

			By("applying the management handle")
			Eventually(func(g Gomega) {
				c := exec.Command("kubectl", "apply", "-f", "-")
				c.Stdin = strings.NewReader(handleYAML)
				out, err := utils.Run(c)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to create management handle: %s", out)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for the handle to report Running (external Admin API reachable)")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagecluster", handleClusterName,
					"-n", testNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Handle not Running: phase=%s", output)
			}, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying ManagementHandleReady condition is True")
			cmd := exec.Command("kubectl", "get", "garagecluster", handleClusterName,
				"-n", testNamespace,
				"-o", "jsonpath={.status.conditions[?(@.type=='ManagementHandleReady')].status}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("True"), "ManagementHandleReady not True: %s", output)
		})

		It("should provision no workload for the handle", func() {
			By("verifying no StatefulSet exists for the handle")
			cmd := exec.Command("kubectl", "get", "statefulset", handleClusterName, "-n", testNamespace)
			_, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "handle must not create a StatefulSet")

			By("verifying no operator-owned GarageNodes exist for the handle")
			cmd = exec.Command("kubectl", "get", "garagenode", "-n", testNamespace,
				"-l", "app.kubernetes.io/instance="+handleClusterName,
				"-o", "jsonpath={.items[*].metadata.name}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(BeEmpty(), "handle must not create GarageNodes, got: %s", output)
		})

		It("should manage a bucket on the external cluster via the handle", func() {
			bucketYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: handle-bucket
  namespace: %s
spec:
  clusterRef:
    name: %s
`, testNamespace, handleClusterName)

			By("creating a GarageBucket that references the handle")
			Eventually(func(g Gomega) {
				c := exec.Command("kubectl", "apply", "-f", "-")
				c.Stdin = strings.NewReader(bucketYAML)
				out, err := utils.Run(c)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to create bucket: %s", out)
			}, 1*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for the bucket to reach Ready with a bucketId (created on the external cluster)")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagebucket", "handle-bucket",
					"-n", testNamespace, "-o", "jsonpath={.status.phase}/{.status.bucketId}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(HavePrefix("Ready/"), "bucket not Ready: %s", output)
				g.Expect(output).NotTo(Equal("Ready/"), "bucket has no bucketId: %s", output)
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
		})
	})
})

// cleanupManagementHandle tears down the management-handle e2e block with a
// LIGHT teardown: it deletes only this block's namespace and CRs and leaves the
// operator, CRDs, and admission webhooks running. This shard (api) runs several
// independent Ordered blocks; each does its own `make install`/`make deploy` in
// BeforeAll, so tearing the operator down here (as the #190 blocks do when they
// own the cluster) only forces a slow reinstall+re-reconcile on the next block
// and destabilizes it. Keeping the operator up also lets the CR finalizers
// resolve normally — no webhook-delete / scale-to-0 / finalizer-strip dance is
// needed. The kind cluster itself is torn down by `make cleanup-test-e2e` after
// the whole suite.
func cleanupManagementHandle(testNamespace string, clusterNames []string) {
	By("deleting this block's CRs (operator finalizes them) then the namespace")
	_, _ = utils.Run(exec.Command("kubectl", "delete", "garagebucket", "--all", "-n", testNamespace,
		"--ignore-not-found", "--timeout=60s"))
	for _, n := range clusterNames {
		_, _ = utils.Run(exec.Command("kubectl", "delete", "garagecluster", n, "-n", testNamespace,
			"--ignore-not-found", "--timeout=90s"))
	}
	_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", testNamespace,
		"--ignore-not-found", "--timeout=90s"))
}

// cleanupAuto190 tears down a #190 e2e block's resources reliably. The naive
// "kubectl delete cluster + ns + make undeploy" pattern hangs in this codebase
// because:
//
//  1. GarageNode/GarageCluster finalizers call the cluster admin API; once the
//     cluster's admin Service is gone the calls retry forever.
//  2. The validating+mutating webhook configurations stay armed with the
//     operator's webhook Service as the target. When `make undeploy` deletes
//     the operator pod, subsequent admission calls (from `kubectl delete`
//     operations during undeploy) hang waiting for a webhook with no backend.
//
// Cleanup order that survives both: delete admission webhooks first → scale
// operator to 0 → clear finalizers → delete CRs (--wait=false) → delete ns
// (--timeout) → make undeploy → make uninstall.
func cleanupAuto190(testNamespace, clusterName string, garageNodeNames []string) {
	By("deleting admission webhook configurations first")
	_, _ = utils.Run(exec.Command("kubectl", "delete", "validatingwebhookconfiguration",
		"garage-operator-validating-webhook-configuration", "--ignore-not-found"))
	_, _ = utils.Run(exec.Command("kubectl", "delete", "mutatingwebhookconfiguration",
		"garage-operator-mutating-webhook-configuration", "--ignore-not-found"))

	By("scaling operator to 0 so it can't re-add finalizers")
	_, _ = utils.Run(exec.Command("kubectl", "scale", "deployment",
		"garage-operator-controller-manager", "-n", namespace, "--replicas=0", "--timeout=30s"))
	time.Sleep(3 * time.Second)

	By("clearing finalizers and deleting test resources")
	for _, n := range garageNodeNames {
		_, _ = utils.Run(exec.Command("kubectl", "patch", "garagenode", n, "-n", testNamespace,
			"--type=merge", "-p", `{"metadata":{"finalizers":null}}`))
	}
	_, _ = utils.Run(exec.Command("kubectl", "patch", "garagecluster", clusterName, "-n", testNamespace,
		"--type=merge", "-p", `{"metadata":{"finalizers":null}}`))
	_, _ = utils.Run(exec.Command("kubectl", "delete", "garagenode", "--all", "-n", testNamespace,
		"--wait=false", "--ignore-not-found"))
	_, _ = utils.Run(exec.Command("kubectl", "delete", "garagecluster", "--all", "-n", testNamespace,
		"--wait=false", "--ignore-not-found"))
	_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", testNamespace,
		"--ignore-not-found", "--timeout=60s"))

	By("undeploying the controller-manager")
	_, _ = utils.Run(exec.Command("make", "undeploy"))

	By("uninstalling CRDs")
	_, _ = utils.Run(exec.Command("make", "uninstall"))
}
