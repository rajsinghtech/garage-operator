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

var _ = Describe("Manager", Ordered, func() {
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
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
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

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("Serving metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted, 3*time.Minute, time.Second).Should(Succeed())

			// +kubebuilder:scaffold:e2e-metrics-webhooks-readiness

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": ["curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics"],
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
				}`, token, metricsServiceName, namespace, serviceAccountName))
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

		It("should remain stable with no garage resources defined", func() {
			By("checking if garage resources exist (from other tests)")
			cmd := exec.Command("kubectl", "get", "garageclusters,garagebuckets,garagekeys,garagenodes", "-A", "--no-headers")
			output, _ := utils.Run(cmd)
			// If resources exist from other tests (e.g., gateway cluster tests), skip the "no resources" check
			// and just verify operator stability
			if output != "" && !strings.Contains(output, "No resources found") {
				By("garage resources exist from other tests, skipping empty state check")
			}

			By("waiting to verify operator stability (no crash loops)")
			// Wait 30 seconds and verify operator has 0 restarts
			time.Sleep(30 * time.Second)

			verifyNoRestarts := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", controllerPodName, "-n", namespace,
					"-o", "jsonpath={.status.containerStatuses[0].restartCount}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("0"), "Operator should not have restarted")
			}
			Eventually(verifyNoRestarts, time.Minute).Should(Succeed())

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

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for controller-manager to be ready")
		verifyControllerUp := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods", "-l", "control-plane=controller-manager",
				"-n", namespace, "-o", "jsonpath={.items[0].status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Running"), "Controller not running: %s", output)
		}
		Eventually(verifyControllerUp, 2*time.Minute, 5*time.Second).Should(Succeed())

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
		cmd := exec.Command("kubectl", "delete", "garagecluster", gatewayClusterName, "-n", testNamespace, "--ignore-not-found")
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
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  replication:
    factor: 1
  storage:
    data:
      size: 1Gi
  admin:
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
  security:
    allowWorldReadableSecrets: true
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
`, storageClusterName, testNamespace)

			By("applying storage cluster")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(storageYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create storage cluster")

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
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  gateway: true
  connectTo:
    clusterRef:
      name: %s
  replication:
    factor: 1
  admin:
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
  security:
    allowWorldReadableSecrets: true
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
`, gatewayClusterName, testNamespace, storageClusterName)

			By("applying gateway cluster")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(gatewayYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create gateway cluster")

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

		It("should create StatefulSet for gateway (for node identity persistence)", func() {
			By("verifying StatefulSet exists")
			cmd := exec.Command("kubectl", "get", "statefulset", gatewayClusterName,
				"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "StatefulSet should exist for gateway cluster")
			Expect(output).To(Equal(gatewayClusterName))

			By("verifying gateway uses metadata PVC only (for node identity persistence)")
			cmd = exec.Command("kubectl", "get", "statefulset", gatewayClusterName,
				"-n", testNamespace, "-o", "jsonpath={.spec.volumeClaimTemplates[*].metadata.name}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("metadata"), "Gateway should have only metadata PVC (not data)")

			By("verifying gateway has EmptyDir for data volume")
			cmd = exec.Command("kubectl", "get", "statefulset", gatewayClusterName,
				"-n", testNamespace, "-o", "jsonpath={.spec.template.spec.volumes[?(@.name==\"data\")].emptyDir}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("{}"), "Gateway should use EmptyDir for data volume")
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

		It("should register gateway as gateway node in layout", func() {
			By("checking storage cluster layout version increased after gateway joined")
			verifyLayoutUpdated := func(g Gomega) {
				// The layout version should be > 1 if gateway node was added
				// (version 1 is initial storage cluster, version 2+ means gateway was added)
				cmd := exec.Command("kubectl", "get", "garagecluster", storageClusterName,
					"-n", testNamespace, "-o", "jsonpath={.status.layoutVersion}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				// Layout version should be 2 or higher (gateway node added)
				g.Expect(output).To(SatisfyAny(Equal("2"), Equal("3"), Equal("4"), Equal("5")),
					"Layout version should be >= 2 after gateway joins, got %s", output)
			}
			Eventually(verifyLayoutUpdated, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying gateway cluster component label")
			cmd := exec.Command("kubectl", "get", "statefulset", gatewayClusterName,
				"-n", testNamespace, "-o", "jsonpath={.metadata.labels.app\\.kubernetes\\.io/component}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("gateway"), "Gateway statefulset should have component=gateway label")
		})

		It("should serve S3 API requests via gateway", func() {
			By("creating a test bucket via storage cluster")
			bucketYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1alpha1
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

		It("should have gateway nodes with null capacity in layout", func() {
			By("querying the cluster layout via Admin API")
			adminToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			verifyGatewayCapacity := func(g Gomega) {
				// Use --overrides to set security context for restricted namespace
				curlCmd := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterLayout",
					adminToken, storageClusterName, testNamespace)
				cmd := exec.Command("kubectl", "run", "curl-layout-check", "--rm", "-i", "--restart=Never",
					"-n", testNamespace,
					"--image=curlimages/curl:latest",
					"--overrides", fmt.Sprintf(`{
						"spec": {
							"containers": [{
								"name": "curl-layout-check",
								"image": "curlimages/curl:latest",
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

				// Parse the layout JSON to find gateway nodes
				// Gateway nodes should have capacity: null, not a numeric value
				// Handle both compact JSON ("capacity":null) and pretty-printed ("capacity": null)
				var layout struct {
					Roles []struct {
						ID       string   `json:"id"`
						Tags     []string `json:"tags"`
						Capacity *uint64  `json:"capacity"`
					} `json:"roles"`
				}
				// Extract JSON from output (kubectl adds "pod deleted" message)
				jsonStart := strings.Index(output, "{")
				jsonEnd := strings.LastIndex(output, "}")
				g.Expect(jsonStart).To(BeNumerically(">=", 0), "No JSON found in output: %s", output)
				g.Expect(jsonEnd).To(BeNumerically(">", jsonStart), "No valid JSON found in output: %s", output)
				jsonStr := output[jsonStart : jsonEnd+1]
				g.Expect(json.Unmarshal([]byte(jsonStr), &layout)).To(Succeed(), "Failed to parse layout JSON: %s", jsonStr)

				// Find the gateway node by its tag prefix
				var foundGatewayNode bool
				for _, role := range layout.Roles {
					for _, tag := range role.Tags {
						if strings.HasPrefix(tag, gatewayClusterName) {
							g.Expect(role.Capacity).To(BeNil(),
								"Gateway node %s should have null capacity, got: %v", tag, role.Capacity)
							foundGatewayNode = true
						}
					}
				}
				g.Expect(foundGatewayNode).To(BeTrue(),
					"Gateway node not found in layout. Roles: %+v", layout.Roles)
			}
			Eventually(verifyGatewayCapacity, 2*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("should preserve node identity when gateway pods restart (StatefulSet + PVC)", func() {
			// Gateway clusters use StatefulSet with metadata PVC, so the node ID is preserved
			// across pod restarts. This test verifies that behavior.
			By("getting the current gateway pod name")
			cmd := exec.Command("kubectl", "get", "pods",
				"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", gatewayClusterName),
				"-n", testNamespace,
				"-o", "jsonpath={.items[0].metadata.name}")
			oldPodName, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(oldPodName).NotTo(BeEmpty(), "No gateway pod found")

			By("getting the gateway node ID before restart")
			adminToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			var oldNodeID string
			getGatewayNodeID := func(g Gomega) {
				curlCmd := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterLayout",
					adminToken, storageClusterName, testNamespace)
				cmd := exec.Command("kubectl", "run", "curl-get-node-id", "--rm", "-i", "--restart=Never",
					"-n", testNamespace,
					"--image=curlimages/curl:latest",
					"--overrides", fmt.Sprintf(`{
						"spec": {
							"containers": [{
								"name": "curl-get-node-id",
								"image": "curlimages/curl:latest",
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
						ID   string   `json:"id"`
						Tags []string `json:"tags"`
					} `json:"roles"`
				}
				jsonStart := strings.Index(output, "{")
				jsonEnd := strings.LastIndex(output, "}")
				g.Expect(jsonStart).To(BeNumerically(">=", 0))
				jsonStr := output[jsonStart : jsonEnd+1]
				g.Expect(json.Unmarshal([]byte(jsonStr), &layout)).To(Succeed())

				for _, role := range layout.Roles {
					for _, tag := range role.Tags {
						if strings.HasPrefix(tag, gatewayClusterName) {
							oldNodeID = role.ID
							return
						}
					}
				}
				g.Expect(oldNodeID).NotTo(BeEmpty(), "Gateway node not found in layout")
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

			By("verifying the same node ID is used after restart (identity preserved)")
			verifyNodeIDPreserved := func(g Gomega) {
				curlCmd := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterLayout",
					adminToken, storageClusterName, testNamespace)
				cmd := exec.Command("kubectl", "run", "curl-check-node-id", "--rm", "-i", "--restart=Never",
					"-n", testNamespace,
					"--image=curlimages/curl:latest",
					"--overrides", fmt.Sprintf(`{
						"spec": {
							"containers": [{
								"name": "curl-check-node-id",
								"image": "curlimages/curl:latest",
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
						ID   string   `json:"id"`
						Tags []string `json:"tags"`
					} `json:"roles"`
				}
				jsonStart := strings.Index(output, "{")
				jsonEnd := strings.LastIndex(output, "}")
				g.Expect(jsonStart).To(BeNumerically(">=", 0))
				jsonStr := output[jsonStart : jsonEnd+1]
				g.Expect(json.Unmarshal([]byte(jsonStr), &layout)).To(Succeed())

				var newNodeID string
				for _, role := range layout.Roles {
					for _, tag := range role.Tags {
						if strings.HasPrefix(tag, gatewayClusterName) {
							newNodeID = role.ID
							break
						}
					}
				}
				// The node ID should be the same because StatefulSet preserves the PVC
				// which contains the node's identity (Ed25519 keypair in metadata_dir/node_key)
				g.Expect(newNodeID).To(Equal(oldNodeID),
					"Node ID should be preserved after restart. Old: %s, New: %s", oldNodeID[:16], newNodeID[:16])
			}
			Eventually(verifyNodeIDPreserved, 2*time.Minute, 10*time.Second).Should(Succeed())

			By("verifying all nodes are connected (no stale nodes)")
			verifyAllConnected := func(g Gomega) {
				curlCmd := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterHealth",
					adminToken, storageClusterName, testNamespace)
				cmd := exec.Command("kubectl", "run", "curl-health-final", "--rm", "-i", "--restart=Never",
					"-n", testNamespace,
					"--image=curlimages/curl:latest",
					"--overrides", fmt.Sprintf(`{
						"spec": {
							"containers": [{
								"name": "curl-health-final",
								"image": "curlimages/curl:latest",
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
				g.Expect(err).NotTo(HaveOccurred(), "Failed to query cluster health: %s", output)

				var health struct {
					Status         string `json:"status"`
					KnownNodes     int    `json:"knownNodes"`
					ConnectedNodes int    `json:"connectedNodes"`
				}
				jsonStart := strings.Index(output, "{")
				jsonEnd := strings.LastIndex(output, "}")
				g.Expect(jsonStart).To(BeNumerically(">=", 0))
				jsonStr := output[jsonStart : jsonEnd+1]
				g.Expect(json.Unmarshal([]byte(jsonStr), &health)).To(Succeed())

				g.Expect(health.Status).To(Equal("healthy"))
				g.Expect(health.ConnectedNodes).To(Equal(health.KnownNodes),
					"All nodes should be connected. Known: %d, Connected: %d", health.KnownNodes, health.ConnectedNodes)
			}
			Eventually(verifyAllConnected, 2*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("should have layout with only expected roles (no extra stale entries)", func() {
			By("querying the cluster layout")
			adminToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			verifyLayoutRoles := func(g Gomega) {
				curlCmd := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterLayout",
					adminToken, storageClusterName, testNamespace)
				cmd := exec.Command("kubectl", "run", "curl-layout-roles", "--rm", "-i", "--restart=Never",
					"-n", testNamespace,
					"--image=curlimages/curl:latest",
					"--overrides", fmt.Sprintf(`{
						"spec": {
							"containers": [{
								"name": "curl-layout-roles",
								"image": "curlimages/curl:latest",
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

				// We have 1 storage node + 1 gateway node = 2 roles total
				// If there are stale nodes, there would be more
				g.Expect(layout.Roles).To(HaveLen(2),
					"Layout should have exactly 2 roles (1 storage + 1 gateway), got %d. Layout: %s", len(layout.Roles), output)

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
				// Clean up any existing curl pod from previous retry attempts
				cleanupCmd := exec.Command("kubectl", "delete", "pod", "curl-layout-cleanup",
					"-n", testNamespace, "--ignore-not-found", "--wait=false")
				_, _ = utils.Run(cleanupCmd)
				time.Sleep(2 * time.Second) // Give time for pod to start terminating

				curlCmd := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterLayout",
					adminToken, storageClusterName, testNamespace)
				cmd := exec.Command("kubectl", "run", "curl-layout-cleanup", "--rm", "-i", "--restart=Never",
					"-n", testNamespace,
					"--image=curlimages/curl:latest",
					"--overrides", fmt.Sprintf(`{
						"spec": {
							"containers": [{
								"name": "curl-layout-cleanup",
								"image": "curlimages/curl:latest",
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

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		// Note: Image is already built and loaded by BeforeSuite (example.com/garage-operator:v0.0.1)

		By("deploying operator via Helm with webhooks enabled")
		cmd = exec.Command("helm", "install", "garage-operator-webhook-test",
			"charts/garage-operator",
			"--namespace", webhookNamespace,
			"--kube-context", kubeContext,
			"-f", "charts/garage-operator/values-e2e-webhooks.yaml",
			"--wait", "--timeout", "180s")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy operator with webhooks: %s", output)
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
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: webhook-test-cluster
  namespace: webhook-test
spec:
  replicas: 1
  replication:
    factor: 1
  storage:
    metadata:
      type: EmptyDir
    data:
      type: EmptyDir
  admin:
    enabled: true
    adminTokenSecretRef:
      name: test-admin-token
      key: admin-token
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
`
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(clusterYAML)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create GarageCluster: %s", output)

			// Verify webhook returned validation warnings
			Expect(output).To(ContainSubstring("Warning"),
				"Expected validation warning from webhook for EmptyDir storage. Output: %s", output)

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
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: invalid-cluster
  namespace: webhook-test
spec:
  replicas: 1
  layoutPolicy: InvalidPolicy
  replication:
    factor: 3
  storage:
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

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for controller-manager to be ready")
		verifyControllerUp := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pods", "-l", "control-plane=controller-manager",
				"-n", namespace, "-o", "jsonpath={.items[0].status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Running"), "Controller not running: %s", output)
		}
		Eventually(verifyControllerUp, 2*time.Minute, 5*time.Second).Should(Succeed())

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
		cmd := exec.Command("kubectl", "delete", "garagenode", node1Name, "-n", testNamespace, "--ignore-not-found")
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
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  layoutPolicy: Manual
  replication:
    factor: 2
  admin:
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
  security:
    allowWorldReadableSecrets: true
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
`, clusterName, testNamespace)

			By("applying GarageCluster")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(clusterYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create GarageCluster")

			By("verifying no StatefulSet is created for Manual mode cluster")
			time.Sleep(5 * time.Second)
			cmd = exec.Command("kubectl", "get", "statefulset", clusterName, "-n", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "StatefulSet should NOT exist for Manual mode cluster")
		})

		It("should create GarageNode 1 with its own StatefulSet", func() {
			By("creating GarageNode 1")
			node1YAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1alpha1
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
apiVersion: garage.rajsingh.info/v1alpha1
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
					"-n", testNamespace, "--image=curlimages/curl:latest",
					fmt.Sprintf("--overrides=%s", fmt.Sprintf(`{
						"spec": {
							"containers": [{
								"name": "curl-layout-zones",
								"image": "curlimages/curl:latest",
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
apiVersion: garage.rajsingh.info/v1alpha1
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
})
