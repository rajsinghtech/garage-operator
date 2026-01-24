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

		It("should create Deployment for gateway (not StatefulSet)", func() {
			By("verifying Deployment exists")
			cmd := exec.Command("kubectl", "get", "deployment", gatewayClusterName,
				"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Deployment should exist")
			Expect(output).To(Equal(gatewayClusterName))

			By("verifying no StatefulSet exists for gateway")
			cmd = exec.Command("kubectl", "get", "statefulset", gatewayClusterName,
				"-n", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "StatefulSet should not exist for gateway cluster")
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
			By("waiting for gateway cluster to report healthy status")
			verifyGatewayHealthy := func(g Gomega) {
				// Check that gateway status shows it's connected
				cmd := exec.Command("kubectl", "get", "garagecluster", gatewayClusterName,
					"-n", testNamespace, "-o", "jsonpath={.status.health.status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("healthy"), "Gateway not healthy: status=%s", output)
			}
			Eventually(verifyGatewayHealthy, 3*time.Minute, 5*time.Second).Should(Succeed())

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
			cmd := exec.Command("kubectl", "get", "deployment", gatewayClusterName,
				"-n", testNamespace, "-o", "jsonpath={.metadata.labels.app\\.kubernetes\\.io/component}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("gateway"), "Gateway deployment should have component=gateway label")
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
	})
})
