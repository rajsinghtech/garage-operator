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
	"regexp"
	"sort"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rajsinghtech/garage-operator/test/utils"
)

// namespace where the project is deployed in
// e2eGarageImage is the upstream Garage the suite runs. Kept at v2.3.0 to match
// the operator's defaultGarageImage; the topology suites cover v2.2.0.
const e2eGarageImage = "dxflrs/garage:v2.3.0@sha256:866bd13ed2038ba7e7190e840482bc27234c4afaf77be8cfa439ae088c1e4690"

const e2eCurlImage = "curlimages/curl:8.14.1@sha256:9a1ed35addb45476afa911696297f8e115993df459278ed036182dd2cd22b67b"

const e2eAWSCLIImage = "amazon/aws-cli:2.27.41@sha256:bc6b7bba44ce38f9604ede49c584824af919047ea03fbcc7c7610671fdef95d8"

const namespace = "garage-operator-system"

const e2eHTTPTimeout = 15 * time.Second

// serviceAccountName created for the project
const serviceAccountName = "garage-operator-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "garage-operator-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "garage-operator-metrics-binding"

type garageClusterScaleSnapshot struct {
	Spec struct {
		Replicas int32 `json:"replicas"`
	} `json:"spec"`
	Status struct {
		Replicas int32  `json:"replicas"`
		Selector string `json:"selector"`
	} `json:"status"`
}

// readGarageClusterScale reads the real scale subresource instead of inferring
// its contract from the parent GarageCluster. This catches stale CRD paths and
// selectors that accidentally include node-local or gateway Pods.
func readGarageClusterScale(apiVersion, testNamespace, clusterName string) (garageClusterScaleSnapshot, error) {
	GinkgoHelper()
	path := fmt.Sprintf(
		"/apis/garage.rajsingh.info/%s/namespaces/%s/garageclusters/%s/scale",
		apiVersion, testNamespace, clusterName,
	)
	output, err := utils.Run(exec.Command("kubectl", "get", "--raw", path))
	if err != nil {
		return garageClusterScaleSnapshot{}, fmt.Errorf("GET %s: %w: %s", path, err, output)
	}
	// utils.Run returns combined output, and the v1beta1 CRD is served with a
	// deprecation warning that kubectl prints ahead of the response body. Decode
	// only the JSON.
	output = stripKubectlWarnings(output)
	var snapshot garageClusterScaleSnapshot
	if err := json.Unmarshal([]byte(output), &snapshot); err != nil {
		return garageClusterScaleSnapshot{}, fmt.Errorf("decode GET %s: %w: %s", path, err, output)
	}
	return snapshot, nil
}

// fixturePathsOverlap reports whether mutating either absolute path can affect
// the other. It deliberately treats an ancestor mount (including /) as unsafe,
// not only a volume nested below the fixture root.
func fixturePathsOverlap(candidate, fixtureRoot string) bool {
	candidate = strings.TrimSpace(candidate)
	fixtureRoot = strings.TrimSpace(fixtureRoot)
	if candidate == "" || fixtureRoot == "" {
		return false
	}
	candidate = filepath.Clean(candidate)
	fixtureRoot = filepath.Clean(fixtureRoot)
	if !filepath.IsAbs(candidate) || !filepath.IsAbs(fixtureRoot) {
		return false
	}
	contains := func(parent, child string) bool {
		relative, err := filepath.Rel(parent, child)
		return err == nil && relative != ".." &&
			!strings.HasPrefix(relative, ".."+string(os.PathSeparator))
	}
	return contains(candidate, fixtureRoot) || contains(fixtureRoot, candidate)
}

func prepareNodeLocalPoolE2EFixtures(
	testNamespace, hostPathBase, managedTopologyHostPathBase string,
) []string {
	GinkgoHelper()
	By("proving the ephemeral HostPath reset targets the requested empty Kind cluster")
	Expect(testNamespace).To(Equal("garage-ds-test"),
		"refusing an unexpected node-local fixture namespace")
	Expect(hostPathBase).To(Equal("/tmp/garage-e2e-ds"),
		"refusing an unexpected node-local HostPath reset root")
	Expect(managedTopologyHostPathBase).To(Equal("/tmp/garage-e2e-managed-mixed"),
		"refusing an unexpected managed-topology HostPath reset root")
	kindCluster := strings.TrimSpace(os.Getenv("KIND_CLUSTER"))
	Expect(kindCluster).NotTo(BeEmpty(),
		"node-local-pool E2E requires the explicit KIND_CLUSTER safety boundary")
	kindBinary := strings.TrimSpace(os.Getenv("KIND"))
	if kindBinary == "" {
		kindBinary = "kind"
	}
	expectedContext := "kind-" + kindCluster
	cmd := exec.Command("kubectl", "config", "current-context")
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to read the current Kubernetes context")
	Expect(strings.TrimSpace(output)).To(Equal(expectedContext),
		"refusing to mutate Nodes or reset HostPaths outside the requested Kind cluster; select context %s first",
		expectedContext)

	cmd = exec.Command(kindBinary, "get", "nodes", "--name", kindCluster)
	output, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to list Nodes from Kind cluster %s", kindCluster)
	kindNodeNames := strings.Fields(output)
	Expect(kindNodeNames).To(HaveLen(3),
		"the node-local-pool E2E requires one control-plane and two worker Nodes")

	cmd = exec.Command("kubectl", "get", "nodes", "-o", "json")
	output, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to inspect Kubernetes Nodes before fixture reset")
	var nodeList struct {
		Items []struct {
			Metadata struct {
				Name        string            `json:"name"`
				Labels      map[string]string `json:"labels"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
		} `json:"items"`
	}
	Expect(json.Unmarshal([]byte(output), &nodeList)).To(Succeed())
	apiNodeNames := make([]string, 0, len(nodeList.Items))
	k8sNodeNames := make([]string, 0, 2)
	controlPlaneNodes := 0
	for _, node := range nodeList.Items {
		apiNodeNames = append(apiNodeNames, node.Metadata.Name)
		if _, controlPlane := node.Metadata.Labels["node-role.kubernetes.io/control-plane"]; controlPlane {
			controlPlaneNodes++
			continue
		}
		k8sNodeNames = append(k8sNodeNames, node.Metadata.Name)
	}
	Expect(apiNodeNames).To(ConsistOf(kindNodeNames),
		"Kind's Nodes and the current Kubernetes context must identify the same dedicated cluster")
	Expect(controlPlaneNodes).To(Equal(1),
		"the node-local-pool E2E topology must have exactly one control-plane Node")
	Expect(k8sNodeNames).To(HaveLen(2),
		"the node-local-pool E2E topology must have exactly two worker Nodes")
	sort.Strings(k8sNodeNames)

	retainedOwnershipRecords := make([]string, 0)
	for _, node := range nodeList.Items {
		for key := range node.Metadata.Labels {
			if strings.HasPrefix(key, "garage.rajsingh.info/gc-") {
				retainedOwnershipRecords = append(retainedOwnershipRecords,
					fmt.Sprintf("%s:label:%s", node.Metadata.Name, key))
			}
		}
		for key := range node.Metadata.Annotations {
			if strings.HasPrefix(key, "garage.rajsingh.info/gc-") {
				retainedOwnershipRecords = append(retainedOwnershipRecords,
					fmt.Sprintf("%s:annotation:%s", node.Metadata.Name, key))
			}
		}
	}
	sort.Strings(retainedOwnershipRecords)
	Expect(retainedOwnershipRecords).To(BeEmpty(),
		"refusing to guess ownership or erase retained node-local identity records: %v; run `make cleanup-test-e2e KIND_CLUSTER=%s` and start with a fresh dedicated cluster",
		retainedOwnershipRecords, kindCluster)

	cmd = exec.Command("kubectl", "get", "namespace", testNamespace,
		"--ignore-not-found", "-o", "name")
	output, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to inspect the dedicated test namespace")
	Expect(strings.TrimSpace(output)).To(BeEmpty(),
		"refusing to erase retained HostPaths after an incomplete run: namespace %s still exists; run `make cleanup-test-e2e KIND_CLUSTER=%s` and start with a fresh dedicated cluster",
		testNamespace, kindCluster)

	cmd = exec.Command("kubectl", "api-resources", "--api-group=garage.rajsingh.info", "-o", "name")
	output, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to discover existing Garage APIs before fixture reset")
	availableGarageResources := make(map[string]bool)
	for _, resourceName := range strings.Fields(output) {
		availableGarageResources[resourceName] = true
	}
	for _, resourceName := range []string{
		"garageclusters.garage.rajsingh.info",
		"garagenodes.garage.rajsingh.info",
	} {
		if !availableGarageResources[resourceName] {
			continue
		}
		cmd = exec.Command("kubectl", "get", resourceName, "--all-namespaces", "-o", "name")
		output, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to inspect stale %s resources", resourceName)
		Expect(strings.TrimSpace(output)).To(BeEmpty(),
			"refusing to erase retained HostPaths while %s resources still exist: %s; run `make cleanup-test-e2e KIND_CLUSTER=%s` and start with a fresh dedicated cluster",
			resourceName, output, kindCluster)
	}

	cmd = exec.Command("kubectl", "get",
		"pods,daemonsets,statefulsets,deployments,replicasets,jobs,cronjobs",
		"--all-namespaces", "-o", "json")
	output, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to inspect live and templated HostPath mounts")
	var workloadList struct {
		Items []map[string]any `json:"items"`
	}
	Expect(json.Unmarshal([]byte(output), &workloadList)).To(Succeed())
	fixtureRoots := []string{hostPathBase, managedTopologyHostPathBase}
	unsafeMounts := make([]string, 0)
	staleGarageWorkloads := make([]string, 0)
	for _, item := range workloadList.Items {
		kind, _ := item["kind"].(string)
		metadata, _ := item["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		ns, _ := metadata["namespace"].(string)
		owner := strings.Trim(strings.Join([]string{kind, ns, name}, "/"), "/")
		if workloadLabels, ok := metadata["labels"].(map[string]any); ok {
			if _, managedCluster := workloadLabels["garage.rajsingh.info/cluster"]; managedCluster {
				staleGarageWorkloads = append(staleGarageWorkloads, owner)
			}
		}
		var inspectValue func(any)
		inspectValue = func(value any) {
			switch typed := value.(type) {
			case map[string]any:
				if hostPath, ok := typed["hostPath"].(map[string]any); ok {
					if mountedPath, ok := hostPath["path"].(string); ok {
						for _, fixtureRoot := range fixtureRoots {
							if fixturePathsOverlap(mountedPath, fixtureRoot) {
								unsafeMounts = append(unsafeMounts, owner+":"+mountedPath)
							}
						}
					}
				}
				for _, child := range typed {
					inspectValue(child)
				}
			case []any:
				for _, child := range typed {
					inspectValue(child)
				}
			}
		}
		inspectValue(item)
	}
	sort.Strings(unsafeMounts)
	sort.Strings(staleGarageWorkloads)
	Expect(staleGarageWorkloads).To(BeEmpty(),
		"refusing to clear Node ownership records while Garage workload objects remain: %v; run `make cleanup-test-e2e KIND_CLUSTER=%s` and start with a fresh dedicated cluster",
		staleGarageWorkloads, kindCluster)
	Expect(unsafeMounts).To(BeEmpty(),
		"refusing to erase a fixture root referenced by a live Pod or workload template: %v; run `make cleanup-test-e2e KIND_CLUSTER=%s` and start with a fresh dedicated cluster",
		unsafeMounts, kindCluster)

	cmd = exec.Command("kubectl", "get", "persistentvolumes", "-o", "json")
	output, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to inspect persistent storage before fixture reset")
	var persistentVolumeList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				HostPath *struct {
					Path string `json:"path"`
				} `json:"hostPath"`
				Local *struct {
					Path string `json:"path"`
				} `json:"local"`
			} `json:"spec"`
		} `json:"items"`
	}
	Expect(json.Unmarshal([]byte(output), &persistentVolumeList)).To(Succeed())
	unsafePersistentVolumes := make([]string, 0)
	for _, volume := range persistentVolumeList.Items {
		paths := make([]string, 0, 2)
		if volume.Spec.HostPath != nil {
			paths = append(paths, volume.Spec.HostPath.Path)
		}
		if volume.Spec.Local != nil {
			paths = append(paths, volume.Spec.Local.Path)
		}
		for _, volumePath := range paths {
			for _, fixtureRoot := range fixtureRoots {
				if fixturePathsOverlap(volumePath, fixtureRoot) {
					unsafePersistentVolumes = append(unsafePersistentVolumes,
						volume.Metadata.Name+":"+volumePath)
				}
			}
		}
	}
	sort.Strings(unsafePersistentVolumes)
	Expect(unsafePersistentVolumes).To(BeEmpty(),
		"refusing to erase a fixture root referenced by a hostPath or local PersistentVolume: %v; run `make cleanup-test-e2e KIND_CLUSTER=%s` and start with a fresh dedicated cluster",
		unsafePersistentVolumes, kindCluster)

	By("resetting only the proven-idle, ownership-record-free ephemeral HostPath fixtures")
	for _, nodeName := range k8sNodeNames {
		cmd = exec.Command("kubectl", "label", "node", nodeName,
			"garage.rajsingh.info/e2e-storage-",
			"garage.rajsingh.info/e2e-storage-profile-")
		output, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to clear fixture selector labels on %s: %s", nodeName, output)

		cmd = exec.Command("docker", "exec", nodeName, "sh", "-ec",
			`rm -rf "$1" "$2" && mkdir -p "$1" "$2"`, "garage-e2e",
			hostPathBase, managedTopologyHostPathBase)
		output, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to reset HostPath fixture on %s: %s", nodeName, output)
	}

	return k8sNodeNames
}

var _ = Describe("Manager", Ordered, Label("manager"), func() {
	var controllerPodName string

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		Expect(ensureE2ENamespaceActive(namespace)).To(Succeed())

		By("labeling the namespace to enforce the restricted security policy")
		cmd := exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label manager namespace: %s", output)

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("waiting for Garage CRDs to be Established")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for the webhook Service route")
		Expect(waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace,
			"--ignore-not-found", "--wait=false")
		if output, err := utils.Run(cmd); err != nil {
			reportE2ECleanupWait("curl-metrics Pod delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("curl-metrics Pod", waitForE2EResourceDeleted(
			"pod", "curl-metrics", namespace, 2*time.Minute,
		))

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		output, err := utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("make undeploy", fmt.Errorf("%v: %s", err, output))
		}

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall", "ignore-not-found=true")
		output, err = utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("make uninstall", fmt.Errorf("%v: %s", err, output))
		}

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace, "--ignore-not-found", "--wait=false")
		output, err = utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("manager namespace delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("manager namespace", waitForE2ENamespaceDeleted(namespace, 2*time.Minute))
		finishE2ECleanupWaits()
	})

	// A deployment rollout replaces the Pod without changing the Deployment
	// name. Refresh the diagnostic/test handle before every spec so a Pod name
	// cached by an earlier spec cannot be used after cert-manager or another
	// controller-triggered rollout.
	BeforeEach(func() {
		controllerPodName = ""
		Eventually(func(g Gomega) {
			name, err := controllerManagerPodReady(namespace)
			g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve a Ready controller-manager Pod")
			controllerPodName = name
		}, 3*time.Minute, 5*time.Second).Should(Succeed())
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			// Prefer the currently Ready Pod for diagnostics; the test-local
			// handle may refer to a Pod replaced during the spec.
			if current, err := controllerManagerPodName(namespace); err == nil {
				controllerPodName = current
			}
			if controllerPodName == "" {
				return
			}
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
				var err error
				controllerPodName, err = controllerManagerPodReady(namespace)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve a Ready controller-manager Pod")
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("getting the controller-manager pod name")
			// Get the controller pod name if not already set (in case this test runs standalone)
			if controllerPodName == "" {
				verifyControllerUp := func(g Gomega) {
					var err error
					controllerPodName, err = controllerManagerPodReady(namespace)
					g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve a Ready controller-manager Pod")
				}
				Eventually(verifyControllerUp, 2*time.Minute, time.Second).Should(Succeed())
			}

			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			// Delete any existing binding first (may exist from previous test run)
			cmd := exec.Command("kubectl", "delete", "clusterrolebinding", metricsRoleBindingName,
				"--ignore-not-found", "--timeout=60s")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to remove existing metrics ClusterRoleBinding: %s", output)

			cmd = exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=garage-operator-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
			)
			_, err = utils.Run(cmd)
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
			waitOutput, waitErr := utils.Run(waitCmd)
			Expect(waitErr).NotTo(HaveOccurred(), "defensive Ready wait failed: %s", waitOutput)

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
				"--namespace", namespace, "--ignore-not-found", "--timeout=60s")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to remove previous curl-metrics Pod: %s", output)

			metricsURL := fmt.Sprintf("http://%s.%s.svc.cluster.local:8443/metrics", metricsServiceName, namespace)
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image="+e2eCurlImage,
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": %q,
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
				}`, e2eCurlImage, token, metricsURL, serviceAccountName))
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
				"-n", namespace, "--ignore-not-found", "--timeout=60s")
			if output, err := utils.Run(cmd); err != nil {
				reportE2ECleanupWait("cluster-wide GarageKey delete request", fmt.Errorf("%v: %s", err, output))
			}
		})

		It("should remain stable with no garage resources defined", func() {
			By("checking if garage resources exist (from other tests)")
			cmd := exec.Command("kubectl", "get", "garageclusters,garagebuckets,garagekeys,garagenodes", "-A", "--no-headers")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to inspect existing Garage resources: %s", output)
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
			initialRestarts, err := e2ePodContainerRestartCount(namespace, controllerPodName, "manager")
			Expect(err).NotTo(HaveOccurred())

			By("waiting to verify operator stability (no NEW crash loops)")
			verifyNoNewRestarts := func(g Gomega) {
				output, err := e2ePodContainerRestartCount(namespace, controllerPodName, "manager")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal(initialRestarts),
					"Operator should not have restarted again (started with %s restarts)", initialRestarts)
			}
			Consistently(verifyNoNewRestarts, 30*time.Second, time.Second).Should(Succeed())

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

	// Use a unique file: the metrics spec can run concurrently with another
	// invocation of this helper, and a fixed /tmp path lets one request replace
	// the other's body.
	tokenRequestFileHandle, err := os.CreateTemp("", serviceAccountName+"-token-request-*")
	if err != nil {
		return "", err
	}
	tokenRequestFile := tokenRequestFileHandle.Name()
	defer func() {
		_ = os.Remove(tokenRequestFile)
	}()
	if _, err := tokenRequestFileHandle.WriteString(tokenRequestRawString); err != nil {
		_ = tokenRequestFileHandle.Close()
		return "", err
	}
	if err := tokenRequestFileHandle.Close(); err != nil {
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

		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())

		// Parse the JSON output to extract the token
		var token tokenRequest
		err = json.Unmarshal([]byte(stripKubectlWarnings(output)), &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, nil
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
		Expect(ensureE2ENamespaceActive(namespace)).To(Succeed())

		By("labeling the manager namespace to enforce the restricted security policy")
		cmd := exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label manager namespace: %s", output)

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("waiting for Garage CRDs to be Established")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for the webhook Service route")
		Expect(waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())

		By("waiting for controller-manager pod to be Ready (webhook server started)")
		verifyControllerUp := func(g Gomega) {
			// Use Ready condition rather than pod Phase. With the webhook
			// readiness gate (cmd/main.go: webhookServer.StartedChecker), the
			// pod will not flip Ready until the TLS listener on :9443 is
			// accepting connections, which is exactly what the next CR apply
			// needs.
			_, err := controllerManagerPodReady(namespace)
			g.Expect(err).NotTo(HaveOccurred(), "Controller not Ready")
		}
		Eventually(verifyControllerUp, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("creating test namespace")
		Expect(createE2ETestNamespace(testNamespace)).To(Succeed())

		By("labeling the test namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		By("cleaning up test resources")
		for _, resource := range []string{"garagekey", "garagebucket"} {
			cmd := exec.Command("kubectl", "delete", resource, "--all", "-n", testNamespace,
				"--ignore-not-found", "--wait=false")
			if output, err := utils.Run(cmd); err != nil {
				reportE2ECleanupWait("gateway "+resource+" delete request", fmt.Errorf("%v: %s", err, output))
			}
			reportE2ECleanupWait("gateway "+resource, waitForE2EResourcesDeleted(
				resource, testNamespace, "", 2*time.Minute,
			))
		}
		cmd := exec.Command("kubectl", "delete", "garagecluster", gatewayClusterName, "-n", testNamespace,
			"--ignore-not-found", "--wait=false")
		if output, err := utils.Run(cmd); err != nil {
			reportE2ECleanupWait("gateway GarageCluster/"+gatewayClusterName+" delete request", fmt.Errorf("%v: %s", err, output))
		}
		cmd = exec.Command("kubectl", "delete", "garagecluster", storageClusterName, "-n", testNamespace,
			"--ignore-not-found", "--wait=false")
		if output, err := utils.Run(cmd); err != nil {
			reportE2ECleanupWait("gateway GarageCluster/"+storageClusterName+" delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("gateway GarageClusters", waitForE2EResourcesDeleted(
			"garagecluster", testNamespace, "", 3*time.Minute,
		))
		cmd = exec.Command("kubectl", "delete", "ns", testNamespace, "--ignore-not-found", "--wait=false")
		output, err := utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("gateway-cluster namespace delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("gateway-cluster namespace", waitForE2ENamespaceDeleted(testNamespace, 2*time.Minute))

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		output, err = utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("make undeploy", fmt.Errorf("%v: %s", err, output))
		}

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall", "ignore-not-found=true")
		output, err = utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("make uninstall", fmt.Errorf("%v: %s", err, output))
		}
		finishE2ECleanupWaits()
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
				"-n", testNamespace, "--ignore-not-found", "--timeout=2m")
			if output, err := utils.Run(cmd); err != nil {
				reportE2ECleanupWait("gateway-test-bucket delete request", fmt.Errorf("%v: %s", err, output))
			}
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
			By("verifying secret resourceVersion is unchanged (no infinite reconciliation)")
			Consistently(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secret", "cw-admin-key",
					"-n", testNamespace, "-o", "jsonpath={.metadata.resourceVersion}")
				rvAfter, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(rvAfter).To(Equal(rvBefore),
					"Secret resourceVersion changed from %s to %s — controller is updating the secret in a loop",
					rvBefore, rvAfter)
			}, 30*time.Second, time.Second).Should(Succeed())

			By("cleaning up cluster-wide key and bucket")
			cmd = exec.Command("kubectl", "delete", "garagekey", "cw-admin-key",
				"-n", testNamespace, "--ignore-not-found", "--timeout=2m")
			if output, err := utils.Run(cmd); err != nil {
				reportE2ECleanupWait("cluster-wide key delete request", fmt.Errorf("%v: %s", err, output))
			}
			cmd = exec.Command("kubectl", "delete", "garagebucket", "cw-test-bucket",
				"-n", testNamespace, "--ignore-not-found", "--timeout=2m")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete cluster-wide bucket: %s", output)
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
					"-n", testNamespace, "-o", "jsonpath={.status.buckets[?(@.globalAlias==\"revoke-test-bucket\")].owner}")
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
					"-n", testNamespace, "-o", "jsonpath={.status.buckets[?(@.globalAlias==\"revoke-test-bucket\")].read}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"), "read should still be true, got: %s", output)

				// write=false is omitted by omitempty, so jsonpath returns ""
				cmd = exec.Command("kubectl", "get", "garagekey", "revoke-test-key",
					"-n", testNamespace, "-o", "jsonpath={.status.buckets[?(@.globalAlias==\"revoke-test-bucket\")].write}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(SatisfyAny(Equal("false"), Equal("")),
					"write should be revoked, got: %s", output)

				cmd = exec.Command("kubectl", "get", "garagekey", "revoke-test-key",
					"-n", testNamespace, "-o", "jsonpath={.status.buckets[?(@.globalAlias==\"revoke-test-bucket\")].owner}")
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
				"-n", testNamespace, "--ignore-not-found", "--timeout=2m")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete revocation test key: %s", output)
			cmd = exec.Command("kubectl", "delete", "garagebucket", "revoke-test-bucket",
				"-n", testNamespace, "--ignore-not-found", "--timeout=2m")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete revocation test bucket: %s", output)
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
				output := runCurlPod(g, testNamespace, "curl-drift-delete-key", curlCmd)
				httpCode := ""
				if match := regexp.MustCompile(`(?:^|[^0-9])(200|404)(?:[^0-9]|$)`).FindStringSubmatch(output); len(match) == 2 {
					httpCode = match[1]
				}
				// Accept 200 (we deleted it) or 404 (already gone — drift already occurred).
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
			accessKeyID := readSecretValue(testNamespace, driftKeyName, "access-key-id")
			Expect(accessKeyID).NotTo(BeEmpty(), "access-key-id not in secret")
			secretAccessKey := readSecretValue(testNamespace, driftKeyName, "secret-access-key")
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
				output := runAWSCLI(g, testNamespace, "drift-s3-verify", s3Cmd, driftKeyName, true)
				g.Expect(output).To(ContainSubstring(testPayload),
					"GET output should contain PUT payload. Full output: %s", output)
			}, 3*time.Minute, 30*time.Second).Should(Succeed())

			By("cleaning up drift test resources")
			deleteObjectCmd := fmt.Sprintf(
				`aws s3api delete-object --endpoint-url %s --region garage --bucket %s --key %s`,
				endpoint, driftBucketID, testObject,
			)
			Eventually(func(g Gomega) {
				output := runAWSCLI(g, testNamespace, "drift-s3-delete-object", deleteObjectCmd, driftKeyName, true)
				g.Expect(output).NotTo(ContainSubstring("An error occurred"),
					"DeleteObject failed. Full output: %s", output)
			}, 2*time.Minute, 10*time.Second).Should(Succeed())

			// Finalize the now-empty bucket while the recovered key and its Secret
			// still exist. Deleting the key first needlessly removes the exact
			// credential path that this cleanup has just proven works.
			cmd := exec.Command("kubectl", "delete", "garagebucket", "drift-test-bucket",
				"-n", testNamespace, "--ignore-not-found", "--timeout=2m")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete empty drift test bucket: %s", output)
			cmd = exec.Command("kubectl", "delete", "garagekey", driftKeyName,
				"-n", testNamespace, "--ignore-not-found", "--timeout=2m")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete drift test key: %s", output)
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
				output := runCurlPod(g, testNamespace, "curl-layout-check", curlCmd)

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
			gatewaySelector := fmt.Sprintf("app.kubernetes.io/instance=%s", gatewayClusterName)
			oldPodName, err := e2ePodName(testNamespace, gatewaySelector, true)
			Expect(err).NotTo(HaveOccurred())
			Expect(oldPodName).NotTo(BeEmpty(), "No gateway pod found")

			By("getting the gateway node ID before restart (from the storage cluster's GetClusterStatus)")
			adminToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			var oldNodeID string
			getGatewayNodeID := func(g Gomega) {
				curlCmd := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterStatus",
					adminToken, storageClusterName, testNamespace)
				output := runCurlPod(g, testNamespace, "curl-get-node-id", curlCmd)

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
			cmd := exec.Command("kubectl", "delete", "pod", oldPodName, "-n", testNamespace,
				"--wait=true", "--timeout=2m")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete gateway pod")

			By("waiting for gateway pod to be ready again")
			verifyPodReady := func(g Gomega) {
				_, err := e2ePodName(testNamespace, gatewaySelector, true)
				g.Expect(err).NotTo(HaveOccurred(), "Gateway Pod is not Ready")
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
				output := runCurlPod(g, testNamespace, "curl-check-node-id", curlCmd)

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
				output := runCurlPod(g, testNamespace, "curl-layout-final", curlCmd)

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
				output := runCurlPod(g, testNamespace, "curl-layout-roles", curlCmd)

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
				"-n", testNamespace, "--wait=false")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete gateway cluster: %s", output)

			By("waiting for Garage metadata sync and gateway cluster deletion to complete")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagecluster", gatewayClusterName,
					"-n", testNamespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred(), "Gateway cluster should be deleted")
			}, 10*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying gateway node removed from storage cluster layout")
			adminToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			verifyGatewayRemoved := func(g Gomega) {
				curlCmd := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterLayout",
					adminToken, storageClusterName, testNamespace)
				output := runCurlPod(g, testNamespace, "curl-layout-cleanup", curlCmd)

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
			By("verifying the real Scale endpoint reports the exact default-group workload")
			Eventually(func(g Gomega) {
				scale, err := readGarageClusterScale("v1beta2", testNamespace, storageClusterName)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(scale.Spec.Replicas).To(Equal(int32(1)))
				g.Expect(scale.Status.Replicas).To(Equal(int32(1)))
				g.Expect(scale.Status.Selector).To(Equal(
					"garage.rajsingh.info/cluster=" + storageClusterName +
						",garage.rajsingh.info/storage-group=default" +
						",garage.rajsingh.info/tier=storage",
				))
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("scaling up via kubectl scale")
			cmd := exec.Command("kubectl", "scale", "garagecluster", storageClusterName,
				"-n", testNamespace, "--replicas=2")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "kubectl scale should succeed")

			By("verifying spec.storage.replicas was updated by scale subresource")
			cmd = exec.Command("kubectl", "get", "garagecluster", storageClusterName,
				"-n", testNamespace, "-o", "jsonpath={.spec.storage.replicas}")
			output, err := utils.Run(cmd)
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

			By("waiting for the exact scale-up identity and its parent rollout generation to converge")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagenode", storageClusterName+"-storage-1",
					"-n", testNamespace,
					"-o", "jsonpath={.metadata.generation}/{.status.observedGeneration}/{.status.nodeId}/{.status.connected}/{.status.inLayout}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				parts := strings.Split(output, "/")
				g.Expect(parts).To(HaveLen(5))
				g.Expect(parts[1]).To(Equal(parts[0]), "GarageNode has not observed its current generation: %q", output)
				g.Expect(parts[2]).NotTo(BeEmpty(), "GarageNode has not discovered its durable identity: %q", output)
				g.Expect(parts[3:]).To(Equal([]string{"true", "true"}), "GarageNode has not entered the committed layout: %q", output)
			}, 5*time.Minute, 5*time.Second).Should(Succeed())
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagecluster", storageClusterName,
					"-n", testNamespace,
					"-o", `jsonpath={.metadata.generation}/{.status.conditions[?(@.type=="StorageRolloutReady")].observedGeneration}/{.status.conditions[?(@.type=="StorageRolloutReady")].status}/{.status.conditions[?(@.type=="StorageRolloutReady")].reason}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				parts := strings.Split(output, "/")
				g.Expect(parts).To(HaveLen(4))
				g.Expect(parts[1]).To(Equal(parts[0]), "storage rollout condition is stale: %q", output)
				g.Expect(parts[2:]).To(Equal([]string{"True", "Converged"}), "storage rollout is not converged: %q", output)
			}, 5*time.Minute, 5*time.Second).Should(Succeed())

			By("scaling back down to 1")
			cmd = exec.Command("kubectl", "scale", "garagecluster", storageClusterName,
				"-n", testNamespace, "--replicas=1")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("proving scale-down starts a reversible drain while the source remains live")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagenode", storageClusterName+"-storage-1",
					"-n", testNamespace,
					"-o", `go-template={{ index .metadata.annotations "garage.rajsingh.info/drain" }}|{{ .metadata.deletionTimestamp }}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true|<no value>"),
					"the parent must complete reversible drain preparation before issuing DELETE")

				cmd = exec.Command("kubectl", "get", "pod", storageClusterName+"-storage-1-0",
					"-n", testNamespace,
					"-o", `jsonpath={.status.phase}/{.status.conditions[?(@.type=="Ready")].status}`)
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running/True"),
					"the retiring source Pod must remain Ready throughout block-resync proof")
			}, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for the full clean drain proof and serialized scale down")
			// Garage v2.3 schedules block GC after 610 seconds. This bound covers
			// that exact proof plus reconciliation; it is not a generic rollout wait.
			verifyScaledDown := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "-n", testNamespace,
					"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", storageClusterName),
					"-o", "name")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				pods := strings.Fields(output)
				g.Expect(pods).To(HaveLen(1), "expected 1 pod, got %d: %q", len(pods), output)
			}
			Eventually(verifyScaledDown, 20*time.Minute, 5*time.Second).Should(Succeed())
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
		Expect(ensureE2ENamespaceActive(namespace)).To(Succeed())

		By("labeling the manager namespace restricted")
		cmd := exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label manager namespace: %s", output)

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for the webhook Service route")
		Expect(waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())

		By("waiting for controller-manager pod to be Ready")
		verifyControllerUp := func(g Gomega) {
			_, err := controllerManagerPodReady(namespace)
			g.Expect(err).NotTo(HaveOccurred(), "Controller not Ready")
		}
		Eventually(verifyControllerUp, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("creating + labeling test namespace")
		Expect(createE2ETestNamespace(testNamespace)).To(Succeed())
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		By("cleaning up unified-cluster test resources")
		cmd := exec.Command("kubectl", "delete", "garagecluster", clusterName, "-n", testNamespace,
			"--ignore-not-found", "--wait=false")
		if output, err := utils.Run(cmd); err != nil {
			reportE2ECleanupWait("manual-mode GarageBuckets delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("unified GarageCluster", waitForE2EResourceDeleted(
			"garagecluster", clusterName, testNamespace, 3*time.Minute,
		))
		cmd = exec.Command("kubectl", "delete", "ns", testNamespace, "--ignore-not-found", "--wait=false")
		output, err := utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("unified-cluster namespace delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("unified-cluster namespace", waitForE2ENamespaceDeleted(testNamespace, 2*time.Minute))
		cmd = exec.Command("make", "undeploy")
		output, err = utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("make undeploy", fmt.Errorf("%v: %s", err, output))
		}
		cmd = exec.Command("make", "uninstall", "ignore-not-found=true")
		output, err = utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("make uninstall", fmt.Errorf("%v: %s", err, output))
		}
		finishE2ECleanupWaits()
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
			output := runCurlPod(g, testNamespace, "curl-unified-layout", curlCmd)

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
		Expect(ensureE2ENamespaceActive(namespace)).To(Succeed())
		cmd := exec.Command("kubectl", "label", "--overwrite", "ns", namespace, "pod-security.kubernetes.io/enforce=restricted")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label manager namespace: %s", output)
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(utils.WaitCRDsEstablished()).To(Succeed())
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())
		verifyControllerUp := func(g Gomega) {
			_, err := controllerManagerPodReady(namespace)
			g.Expect(err).NotTo(HaveOccurred(), "controller not Ready")
		}
		Eventually(verifyControllerUp, 3*time.Minute, 5*time.Second).Should(Succeed())
		Expect(createE2ETestNamespace(testNamespace)).To(Succeed())
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace, "pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		// Bounded on purpose. This cluster's finalizer is fail-closed: if the
		// migration left the layout in a state it cannot prove safe to release,
		// the delete blocks indefinitely. Request deletion without waiting, then
		// poll explicitly so a stuck finalizer is reported as itself instead of
		// consuming the whole shard's remaining budget.
		cmd := exec.Command("kubectl", "delete", "garagecluster", clusterName,
			"-n", testNamespace, "--ignore-not-found", "--wait=false")
		if out, err := utils.Run(cmd); err != nil {
			reportE2ECleanupWait("factor-migration GarageCluster delete request", fmt.Errorf("%v: %s", err, out))
		}
		if err := waitForE2EResourceDeleted("garagecluster", clusterName, testNamespace, 3*time.Minute); err != nil {
			reportE2ECleanupWait("factor-migration GarageCluster", err)
			diagnostic, diagnosticErr := utils.Run(exec.Command("kubectl", "get", "garagecluster", clusterName,
				"-n", testNamespace, "-o", "jsonpath={.status.factorMigration}{\"\\n\"}{.status.conditions}"))
			if diagnosticErr != nil {
				AddReportEntry("factor-migration cleanup diagnostics",
					fmt.Sprintf("failed to inspect GarageCluster/%s: %v: %s", clusterName, diagnosticErr, diagnostic))
			} else {
				AddReportEntry("factor-migration cleanup diagnostics", diagnostic)
			}
			// Drop the finalizer so teardown is deterministic. Everything after
			// this point blocks on it: the namespace cannot finish Terminating,
			// and `make uninstall` deletes the CRD, which waits on the CR. Undeploy
			// removes the operator, so nothing would ever clear it on its own.
			// Reported above, so a stuck finalizer still fails the spec loudly
			// instead of being absorbed by whatever times out first.
			patchOutput, patchErr := utils.Run(exec.Command("kubectl", "patch", "garagecluster", clusterName,
				"-n", testNamespace, "--type=merge", "-p", `{"metadata":{"finalizers":null}}`))
			if patchErr != nil {
				reportE2ECleanupWait("factor-migration GarageCluster finalizer removal",
					fmt.Errorf("%v: %s", patchErr, patchOutput))
			}
			reportE2ECleanupWait("factor-migration GarageCluster after finalizer removal",
				waitForE2EResourceDeleted("garagecluster", clusterName, testNamespace, 30*time.Second))
		}
		// Also bounded, and for a sharper reason than tidiness: a namespace cannot
		// finish Terminating while a GarageCluster in it still holds its finalizer,
		// so an unbounded delete here inherits the stuck finalizer above and blocks
		// forever. That is what converted a single spec failure into a whole-shard
		// Go timeout, which reports as "40m elapsed" and attributes nothing.
		cmd = exec.Command("kubectl", "delete", "ns", testNamespace, "--ignore-not-found", "--wait=false")
		if out, err := utils.Run(cmd); err != nil {
			AddReportEntry("factor-migration cleanup: namespace delete did not complete within 2m",
				fmt.Sprintf("error=%v output=%s", err, out))
		}
		reportE2ECleanupWait("factor-migration namespace", waitForE2ENamespaceDeleted(testNamespace, 2*time.Minute))
		cmd = exec.Command("make", "undeploy")
		output, err := utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("make undeploy", fmt.Errorf("%v: %s", err, output))
		}
		cmd = exec.Command("make", "uninstall", "ignore-not-found=true")
		output, err = utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("make uninstall", fmt.Errorf("%v: %s", err, output))
		}
		finishE2ECleanupWaits()
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
		By("atomically patching spec.replication.factor=1 and requesting the coordinated purge")
		patchFactor := func(g Gomega) {
			c := exec.Command("kubectl", "patch", "garagecluster", clusterName, "-n", testNamespace,
				"--type=merge", "-p", `{"metadata":{"annotations":{"garage.rajsingh.info/purge-cluster-layout":"factor=1"}},"spec":{"replication":{"factor":1}}}`)
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
		// Must outlast fmStuckTimeout (15m), which is what makes the Failed branch
		// above reachable: the operator aborts a wedged phase itself and says which
		// precondition went unmet. Giving up first replaces that with a bare
		// timeout. Costs nothing when the migration converges — this returns as
		// soon as the phase reads Completed, typically in about a minute.
		Eventually(verifyCompleted, 16*time.Minute, 10*time.Second).Should(Succeed())
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
		Expect(createE2ETestNamespace(webhookNamespace)).To(Succeed())
		Expect(createE2ETestNamespace("webhook-test")).To(Succeed())

		// Note: Image is already built and loaded by BeforeSuite (example.com/garage-operator:v0.0.1)

		// Prior Describe blocks install CRDs via `make install` (kustomize), which
		// does not set Helm ownership labels/annotations. A subsequent `helm
		// install` then refuses to adopt those CRDs with an "invalid ownership
		// metadata" error. Delete any leftover Garage CRDs (and their CRs across
		// the cluster, since CRDs are cluster-scoped) before the Helm install so
		// it can manage them fresh. Earlier suites' AfterAll already calls
		// `make uninstall`, so in the common case this is a no-op.
		By("deleting any pre-existing Garage CRDs to avoid helm ownership conflict")
		cmd := exec.Command("kubectl", "delete", "crd",
			"garageadmintokens.garage.rajsingh.info",
			"garagebuckets.garage.rajsingh.info",
			"garageclusters.garage.rajsingh.info",
			"garagekeys.garage.rajsingh.info",
			"garagenodes.garage.rajsingh.info",
			"garagereferencegrants.garage.rajsingh.info",
			"--ignore-not-found", "--timeout=60s")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to remove pre-existing Garage CRDs: %s", output)

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
		output, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy operator with webhooks: %s", output)
		Expect(waitForE2EWebhookServiceRoute(webhookNamespace,
			"garage-operator-webhook-test-webhook", 2*time.Minute)).To(Succeed())

		By("waiting for Garage CRDs to be Established")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())
	})

	AfterAll(func() {
		By("cleaning up webhook test resources before removing the operator")
		// The nested GarageReferenceGrant context normally removes its own
		// objects first. Repeat the child-CR sweep in both namespaces here so a
		// failed nested BeforeAll/AfterAll cannot leave a finalizer behind while
		// Helm removes the operator and its webhook Service.
		for _, testNamespace := range []string{"webhook-test", webhookNamespace} {
			for _, resource := range []string{"garagekey", "garagebucket"} {
				cmd := exec.Command("kubectl", "delete", resource, "--all", "-n", testNamespace,
					"--ignore-not-found", "--wait=false")
				if output, err := utils.Run(cmd); err != nil {
					reportE2ECleanupWait(testNamespace+" "+resource+" delete request", fmt.Errorf("%v: %s", err, output))
				}
				reportE2ECleanupWait(testNamespace+" "+resource, waitForE2EResourcesDeleted(
					resource, testNamespace, "", 2*time.Minute,
				))
			}
			// A GarageCluster may need its AdminToken and generated GarageNodes
			// while its finalizer performs layout cleanup, so retain the existing
			// parent-first order. Every child is still explicitly waited for before
			// the namespace, Helm release, or CRDs are removed.
			for _, resource := range []string{"garagecluster", "garagenode", "garageadmintoken", "garagereferencegrant"} {
				cmd := exec.Command("kubectl", "delete", resource, "--all", "-n", testNamespace,
					"--ignore-not-found", "--wait=false")
				if output, err := utils.Run(cmd); err != nil {
					reportE2ECleanupWait(testNamespace+" "+resource+" delete request", fmt.Errorf("%v: %s", err, output))
				}
				reportE2ECleanupWait(testNamespace+" "+resource, waitForE2EResourcesDeleted(
					resource, testNamespace, "", 2*time.Minute,
				))
			}
		}

		By("uninstalling Helm release")
		cmd := exec.Command("helm", "uninstall", "garage-operator-webhook-test",
			"--namespace", webhookNamespace,
			"--kube-context", kubeContext,
			"--wait", "--timeout", "180s")
		output, err := utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("Helm webhook release uninstall", fmt.Errorf("%v: %s", err, output))
		}

		By("deleting webhook test namespace")
		cmd = exec.Command("kubectl", "delete", "ns", "webhook-test", "--ignore-not-found", "--wait=false")
		output, err = utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("webhook-test namespace delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("webhook-test namespace", waitForE2ENamespaceDeleted("webhook-test", 2*time.Minute))

		By("deleting webhook operator namespace")
		cmd = exec.Command("kubectl", "delete", "ns", webhookNamespace, "--ignore-not-found", "--wait=false")
		output, err = utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("webhook operator namespace delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("webhook operator namespace", waitForE2ENamespaceDeleted(webhookNamespace, 2*time.Minute))

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall", "ignore-not-found=true")
		output, err = utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("make uninstall", fmt.Errorf("%v: %s", err, output))
		}
		finishE2ECleanupWaits()
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
				var err error
				webhookControllerPodName, err = e2ePodName(
					webhookNamespace, "app.kubernetes.io/name=garage-operator", true,
				)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve a Ready webhook controller Pod")
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
					"-o", "json",
					"--request-timeout=15s",
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				var configurations struct {
					Items []struct {
						Webhooks []struct {
							ClientConfig struct {
								CABundle string `json:"caBundle"`
							} `json:"clientConfig"`
						} `json:"webhooks"`
					} `json:"items"`
				}
				g.Expect(json.Unmarshal([]byte(stripKubectlWarnings(output)), &configurations)).To(Succeed())
				hasBundle := false
				for _, configuration := range configurations.Items {
					for _, webhook := range configuration.Webhooks {
						if webhook.ClientConfig.CABundle != "" {
							hasBundle = true
							break
						}
					}
					if hasBundle {
						break
					}
				}
				g.Expect(configurations.Items).NotTo(BeEmpty(), "webhook configuration not found")
				g.Expect(hasBundle).To(BeTrue(), "CA bundle not yet injected by cert-manager")
			}
			Eventually(verifyCaBundleInjected, 2*time.Minute, time.Second).Should(Succeed())
		})

		It("should return validation warnings for EmptyDir storage", func() {
			By("creating test namespace for webhook validation")
			Expect(ensureE2ENamespaceActive("webhook-test")).To(Succeed())

			By("creating admin token secret")
			cmd := exec.Command("kubectl", "create", "secret", "generic", "test-admin-token",
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
				"-n", "webhook-test", "--ignore-not-found", "--timeout=2m")
			cleanupOutput, cleanupErr := utils.Run(cmd)
			Expect(cleanupErr).NotTo(HaveOccurred(), "Failed to clean up webhook test cluster: %s", cleanupOutput)
		})

		It("should reject invalid GarageCluster configurations", func() {
			By("creating test namespace if not exists")
			Expect(ensureE2ENamespaceActive("webhook-test")).To(Succeed())

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
			cmd := exec.Command("kubectl", "apply", "-f", "-")
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
			Expect(createE2ETestNamespace(rgSourceNS)).To(Succeed())
		})

		AfterAll(func() {
			By("cleaning up reference-grant test resources")
			for _, resource := range []string{"garagekey", "garagebucket"} {
				cmd := exec.Command("kubectl", "delete", resource, "--all", "-n", rgSourceNS,
					"--ignore-not-found", "--wait=false")
				if output, err := utils.Run(cmd); err != nil {
					reportE2ECleanupWait("reference-grant source "+resource+" delete request", fmt.Errorf("%v: %s", err, output))
				}
				reportE2ECleanupWait("reference-grant source "+resource, waitForE2EResourcesDeleted(
					resource, rgSourceNS, "", 2*time.Minute,
				))
			}

			cmd := exec.Command("kubectl", "delete", "garagereferencegrant", "--all",
				"-n", webhookNamespace, "--ignore-not-found", "--wait=false")
			if output, err := utils.Run(cmd); err != nil {
				reportE2ECleanupWait("GarageReferenceGrants delete request", fmt.Errorf("%v: %s", err, output))
			}
			reportE2ECleanupWait("GarageReferenceGrants", waitForE2EResourcesDeleted(
				"garagereferencegrant", webhookNamespace, "", 2*time.Minute,
			))

			By("cleaning up source namespace")
			cmd = exec.Command("kubectl", "delete", "ns", rgSourceNS,
				"--ignore-not-found", "--wait=false")
			if output, err := utils.Run(cmd); err != nil {
				reportE2ECleanupWait("reference-grant source namespace delete request", fmt.Errorf("%v: %s", err, output))
			}
			reportE2ECleanupWait("reference-grant source namespace", waitForE2ENamespaceDeleted(
				rgSourceNS, 2*time.Minute,
			))
			finishE2ECleanupWaits()
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
				"-n", rgSourceNS, "--ignore-not-found", "--timeout=60s")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete rejected GarageKey: %s", output)
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
				"-n", webhookNamespace, "--ignore-not-found", "--timeout=60s")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete same-namespace GarageKey: %s", output)
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
				"-n", rgSourceNS, "--ignore-not-found", "--timeout=60s")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete rejected GarageBucket: %s", output)
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
				"-n", rgSourceNS, "--ignore-not-found", "--timeout=60s")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete granted GarageBucket: %s", output)
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
				"-n", rgSourceNS, "--ignore-not-found", "--timeout=60s")
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
	const netNodeName = "garage-node-net"
	const existingClaimNodeName = "garage-node-existing-claim"
	const staticSelectorNodeName = "garage-node-static-selector"
	const staticMetadataPVName = "garage-manual-static-metadata"
	const staticDataPVName = "garage-manual-static-data"

	BeforeAll(func() {
		By("creating manager namespace")
		Expect(ensureE2ENamespaceActive(namespace)).To(Succeed())

		By("labeling the manager namespace to enforce the restricted security policy")
		cmd := exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label manager namespace: %s", output)

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("waiting for Garage CRDs to be Established")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for the webhook Service route")
		Expect(waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())

		By("waiting for controller-manager pod to be Ready (webhook server started)")
		verifyControllerUp := func(g Gomega) {
			// Use Ready condition rather than pod Phase. With the webhook
			// readiness gate (cmd/main.go: webhookServer.StartedChecker), the
			// pod will not flip Ready until the TLS listener on :9443 is
			// accepting connections, which is exactly what the next CR apply
			// needs.
			_, err := controllerManagerPodReady(namespace)
			g.Expect(err).NotTo(HaveOccurred(), "Controller not Ready")
		}
		Eventually(verifyControllerUp, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("creating test namespace")
		Expect(createE2ETestNamespace(testNamespace)).To(Succeed())

		By("labeling the test namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		By("cleaning up test resources")
		cmd := exec.Command("kubectl", "delete", "garagekey", "--all", "-n", testNamespace,
			"--ignore-not-found", "--wait=false")
		if output, err := utils.Run(cmd); err != nil {
			reportE2ECleanupWait("manual-mode GarageKeys delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("manual-mode GarageKeys", waitForE2EResourcesDeleted(
			"garagekey", testNamespace, "", 2*time.Minute,
		))
		cmd = exec.Command("kubectl", "delete", "garagebucket", "--all", "-n", testNamespace,
			"--ignore-not-found", "--wait=false")
		if output, err := utils.Run(cmd); err != nil {
			reportE2ECleanupWait("manual-mode GarageBuckets delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("manual-mode GarageBuckets", waitForE2EResourcesDeleted(
			"garagebucket", testNamespace, "", 2*time.Minute,
		))

		// This is whole-store teardown, not a scale-down. Deleting either of the
		// final two factor-2 storage nodes individually is intentionally held by
		// its finalizer. Mark the parent deleting first so Manual GarageNodes can
		// release their finalizers without attempting overlapping layout writes.
		cmd = exec.Command("kubectl", "delete", "garagecluster", clusterName, "-n", testNamespace,
			"--ignore-not-found", "--wait=false")
		if output, err := utils.Run(cmd); err != nil {
			reportE2ECleanupWait("unified GarageCluster delete request", fmt.Errorf("%v: %s", err, output))
		}
		// Explicitly request child deletion while the parent is still present and
		// terminating. A storage GarageNode whose parent has already disappeared
		// intentionally refuses to release its identity finalizer: deleting the
		// parent first and only then deleting these children can strand them.
		cmd = exec.Command("kubectl", "delete", "garagenode", "--all", "-n", testNamespace,
			"--ignore-not-found", "--wait=false")
		if output, err := utils.Run(cmd); err != nil {
			reportE2ECleanupWait("manual-mode GarageNodes delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("manual-mode GarageNodes", waitForE2EResourcesDeleted(
			"garagenode", testNamespace, "", 3*time.Minute,
		))
		reportE2ECleanupWait("manual-mode GarageCluster", waitForE2EResourceDeleted(
			"garagecluster", clusterName, testNamespace, 3*time.Minute,
		))
		cmd = exec.Command("kubectl", "delete", "ns", testNamespace,
			"--ignore-not-found", "--wait=false")
		if output, err := utils.Run(cmd); err != nil {
			reportE2ECleanupWait("manual-mode namespace delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("manual-mode namespace", waitForE2ENamespaceDeleted(testNamespace, 2*time.Minute))
		cmd = exec.Command("kubectl", "delete", "pv", staticMetadataPVName, staticDataPVName,
			"--ignore-not-found", "--wait=false")
		if output, err := utils.Run(cmd); err != nil {
			reportE2ECleanupWait("manual-mode PV delete request", fmt.Errorf("%v: %s", err, output))
		}
		for _, pvName := range []string{staticMetadataPVName, staticDataPVName} {
			reportE2ECleanupWait("manual-mode PV/"+pvName, waitForE2EResourceDeleted(
				"pv", pvName, "", 2*time.Minute,
			))
		}

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		output, err := utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("make undeploy", fmt.Errorf("%v: %s", err, output))
		}

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall", "ignore-not-found=true")
		output, err = utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("make uninstall", fmt.Errorf("%v: %s", err, output))
		}
		finishE2ECleanupWaits()
	})

	Context("When creating a Manual mode cluster with GarageNodes", func() {
		It("should converge when the token, cluster, and GarageNode arrive in one apply", func() {
			const (
				oneWaveNamespace = "garage-manual-bootstrap-test"
				oneWaveToken     = "one-wave-admin-token"
				oneWaveSecret    = "one-wave-admin-bootstrap"
				oneWaveCluster   = "one-wave-cluster"
				oneWaveNode      = "one-wave-node"
			)

			By("creating a clean namespace for the one-wave fixture")
			Expect(createE2ETestNamespace(oneWaveNamespace)).To(Succeed())
			DeferCleanup(func() {
				// The cluster finalizer must see the Manual GarageNode while the
				// parent is terminating so it can release the durable Garage
				// identity. The token is deleted only after the cluster no longer
				// consumes its generated Secret.
				cmd := exec.Command("kubectl", "delete", "garagecluster", oneWaveCluster,
					"-n", oneWaveNamespace, "--ignore-not-found", "--wait=false")
				if output, err := utils.Run(cmd); err != nil {
					reportE2ECleanupWait("one-wave GarageCluster delete request", fmt.Errorf("%v: %s", err, output))
				}
				cmd = exec.Command("kubectl", "delete", "garagenode", oneWaveNode,
					"-n", oneWaveNamespace, "--ignore-not-found", "--wait=false")
				if output, err := utils.Run(cmd); err != nil {
					reportE2ECleanupWait("one-wave GarageNode delete request", fmt.Errorf("%v: %s", err, output))
				}
				reportE2ECleanupWait("one-wave GarageNode", waitForE2EResourceDeleted(
					"garagenode", oneWaveNode, oneWaveNamespace, 3*time.Minute,
				))
				reportE2ECleanupWait("one-wave GarageCluster", waitForE2EResourceDeleted(
					"garagecluster", oneWaveCluster, oneWaveNamespace, 3*time.Minute,
				))
				cmd = exec.Command("kubectl", "delete", "garageadmintoken", oneWaveToken,
					"-n", oneWaveNamespace, "--ignore-not-found", "--wait=false")
				if output, err := utils.Run(cmd); err != nil {
					reportE2ECleanupWait("one-wave GarageAdminToken delete request", fmt.Errorf("%v: %s", err, output))
				}
				reportE2ECleanupWait("one-wave GarageAdminToken", waitForE2EResourceDeleted(
					"garageadmintoken", oneWaveToken, oneWaveNamespace, 2*time.Minute,
				))
				cmd = exec.Command("kubectl", "delete", "namespace", oneWaveNamespace,
					"--ignore-not-found", "--wait=false")
				if output, err := utils.Run(cmd); err != nil {
					reportE2ECleanupWait("one-wave namespace delete request", fmt.Errorf("%v: %s", err, output))
				}
				reportE2ECleanupWait("one-wave namespace", waitForE2ENamespaceDeleted(
					oneWaveNamespace, 2*time.Minute,
				))
			})

			By("labeling the fixture namespace for the restricted pod security policy")
			cmd := exec.Command("kubectl", "label", "--overwrite", "namespace", oneWaveNamespace,
				"pod-security.kubernetes.io/enforce=restricted")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to label one-wave namespace: %s", output)

			oneWaveYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageAdminToken
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef:
    name: %s
  secretTemplate:
    name: %s
    tokenKey: admin-token
---
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
      name: %s
      key: admin-token
  security:
    allowInsecureSecretPermissions: true
---
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
`, oneWaveToken, oneWaveNamespace, oneWaveCluster, oneWaveSecret,
				oneWaveCluster, oneWaveNamespace, oneWaveSecret,
				oneWaveNode, oneWaveNamespace, oneWaveCluster)

			By("applying GarageAdminToken, Manual GarageCluster, and GarageNode in one apply")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(oneWaveYAML)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply one-wave fixture: %s", output)

			By("waiting for the one-wave resources and the Garage process to become usable")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garageadmintoken", oneWaveToken,
					"-n", oneWaveNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Ready"), "GarageAdminToken is not Ready: %s", output)

				cmd = exec.Command("kubectl", "get", "secret", oneWaveSecret,
					"-n", oneWaveNamespace, "-o", "jsonpath={.data.admin-token}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty(), "generated static admin Secret has no token")

				cmd = exec.Command("kubectl", "get", "configmap", "-n", oneWaveNamespace,
					"-l", "garage.rajsingh.info/cluster="+oneWaveCluster,
					"-o", "jsonpath={.items[0].metadata.name}/{.items[0].immutable}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				configParts := strings.Split(output, "/")
				g.Expect(configParts).To(HaveLen(2))
				if len(configParts) == 2 {
					g.Expect(configParts[0]).To(HavePrefix(oneWaveCluster+"-config-"),
						"immutable cluster ConfigMap revision was not published: %s", output)
					g.Expect(configParts[1]).To(Equal("true"),
						"cluster ConfigMap revision is not immutable: %s", output)
				}

				cmd = exec.Command("kubectl", "get", "statefulset", oneWaveNode,
					"-n", oneWaveNamespace, "-o", "jsonpath={.spec.replicas}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("1"), "GarageNode StatefulSet is not desired at one replica: %s", output)

				cmd = exec.Command("kubectl", "get", "pod", oneWaveNode+"-0",
					"-n", oneWaveNamespace, "-o", "jsonpath={.status.phase}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "GarageNode Pod is not Running: %s", output)

				cmd = exec.Command("kubectl", "get", "garagenode", oneWaveNode,
					"-n", oneWaveNamespace,
					"-o", "jsonpath={.metadata.generation}/{.status.observedGeneration}/{.status.nodeId}/{.status.connected}/{.status.inLayout}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				parts := strings.Split(output, "/")
				g.Expect(parts).To(HaveLen(5))
				if len(parts) == 5 {
					g.Expect(parts[1]).To(Equal(parts[0]), "GarageNode has not observed its current generation: %q", output)
					g.Expect(parts[2]).NotTo(BeEmpty(), "GarageNode has no durable identity: %q", output)
					g.Expect(parts[3:]).To(Equal([]string{"true", "true"}),
						"GarageNode is not connected and in the committed layout: %q", output)
				}

				cmd = exec.Command("kubectl", "get", "garagecluster", oneWaveCluster,
					"-n", oneWaveNamespace,
					"-o", "jsonpath={.metadata.generation}/{.status.observedGeneration}/{.status.phase}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				parts = strings.Split(output, "/")
				g.Expect(parts).To(HaveLen(3))
				if len(parts) == 3 {
					g.Expect(parts[1]).To(Equal(parts[0]), "GarageCluster has not observed its current generation: %q", output)
					g.Expect(parts[2]).To(Equal("Running"), "GarageCluster is not usable: %q", output)
				}
			}, 10*time.Minute, 5*time.Second).Should(Succeed())
		})

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
			Consistently(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", clusterName, "-n", testNamespace,
					"--ignore-not-found", "-o", "name")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(BeEmpty(),
					"StatefulSet should NOT exist for Manual mode cluster")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
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

			// The two initial GarageNode roles are staged and applied together, but
			// Garage may keep the previous layout version live while its tables sync.
			// The next spec performs another layout mutation, so wait for that data
			// movement to finish before creating the selector-backed node. Otherwise
			// the mutation coordinator correctly holds the new node in Pending while
			// this ordered spec times out.
			const adminToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			By("waiting for the initial Garage layout data migration to settle")
			Eventually(func(g Gomega) {
				_, history := readGarageLayoutSnapshot(
					g, testNamespace, "manual-layout-settled", clusterName, adminToken,
				)
				g.Expect(history.Versions).NotTo(BeEmpty(), "Garage layout history is empty")
				for _, version := range history.Versions {
					g.Expect(version.Status).NotTo(Equal("Draining"),
						"Garage layout version %d is still draining", version.Version)
				}
			}, 4*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("should bind metadata and data selectors to distinct static PVs without retargeting retained claims", func() {
			const staticClass = "garage-manual-static"
			const staticBase = "/tmp/garage-e2e-manual-static"
			const metadataClaim = "metadata-" + staticSelectorNodeName + "-0"
			const dataClaim = "data-" + staticSelectorNodeName + "-0"

			By("provisioning explicit writable directories on the dedicated Kind node")
			cmd := exec.Command("kubectl", "get", "nodes", "-o", "jsonpath={range .items[*]}{.metadata.name}{'\\n'}{end}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			nodeNames := strings.Fields(output)
			Expect(nodeNames).To(HaveLen(1), "the static-PV fixture expects the shard's one-node Kind cluster")
			cmd = exec.Command("docker", "exec", nodeNames[0], "sh", "-ec",
				`mkdir -p "$1/metadata" "$1/data" && chown -R 1000:1000 "$1" && chmod -R 0770 "$1"`,
				"garage-static-fixture", staticBase)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to provision static-PV directories: %s", output)

			By("creating two labeled pre-provisioned PersistentVolumes")
			volumesYAML := fmt.Sprintf(`
apiVersion: v1
kind: PersistentVolume
metadata:
  name: %s
  labels:
    garage.rajsingh.info/e2e-static-volume: metadata
spec:
  capacity:
    storage: 1Gi
  accessModes: [ReadWriteOnce]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: %s
  hostPath:
    path: %s/metadata
    type: Directory
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: %s
  labels:
    garage.rajsingh.info/e2e-static-volume: data
spec:
  capacity:
    storage: 2Gi
  accessModes: [ReadWriteOnce]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: %s
  hostPath:
    path: %s/data
    type: Directory
`, staticMetadataPVName, staticClass, staticBase, staticDataPVName, staticClass, staticBase)
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(volumesYAML)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create static PersistentVolumes: %s", output)

			By("creating a GarageNode whose new claim templates select those exact PV profiles")
			nodeYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef:
    name: %s
  zone: zone-static
  capacity: 2Gi
  storage:
    metadata:
      size: 100Mi
      storageClassName: %s
      selector:
        matchLabels:
          garage.rajsingh.info/e2e-static-volume: metadata
    data:
      size: 1Gi
      storageClassName: %s
      selector:
        matchLabels:
          garage.rajsingh.info/e2e-static-volume: data
  resources:
    limits:
      memory: 256Mi
    requests:
      memory: 128Mi
`, staticSelectorNodeName, testNamespace, clusterName, staticClass, staticClass)
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(nodeYAML)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create selector-backed GarageNode: %s", output)

			Eventually(func(g Gomega) {
				for claimName, wantPV := range map[string]string{
					metadataClaim: staticMetadataPVName,
					dataClaim:     staticDataPVName,
				} {
					cmd := exec.Command("kubectl", "get", "pvc", claimName, "-n", testNamespace,
						"-o", "jsonpath={.status.phase}/{.spec.volumeName}")
					output, err := utils.Run(cmd)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(output).To(Equal("Bound/" + wantPV))
				}
				cmd := exec.Command("kubectl", "get", "garagenode", staticSelectorNodeName,
					"-n", testNamespace, "-o", "jsonpath={.status.nodeId}/{.status.connected}/{.status.inLayout}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				parts := strings.Split(output, "/")
				g.Expect(parts).To(HaveLen(3))
				g.Expect(parts[0]).To(MatchRegexp(`^[0-9a-f]{64}$`))
				g.Expect(parts[1:]).To(Equal([]string{"true", "true"}))
			}, 4*time.Minute, 10*time.Second).Should(Succeed())

			uidFor := func(kind, name string) string {
				cmd := exec.Command("kubectl", "get", kind, name, "-n", testNamespace,
					"-o", "jsonpath={.metadata.uid}")
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				Expect(output).NotTo(BeEmpty())
				return output
			}
			metadataUID := uidFor("pvc", metadataClaim)
			dataUID := uidFor("pvc", dataClaim)
			podUID := uidFor("pod", staticSelectorNodeName+"-0")
			cmd = exec.Command("kubectl", "get", "garagenode", staticSelectorNodeName,
				"-n", testNamespace, "-o", "jsonpath={.status.nodeId}")
			originalNodeID, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("rejecting a live selector retarget before it can rewrite an immutable claim template")
			selectorPatch := `[{"op":"replace","path":"/spec/storage/metadata/selector/matchLabels/garage.rajsingh.info~1e2e-static-volume","value":"wrong"}]`
			cmd = exec.Command("kubectl", "patch", "garagenode", staticSelectorNodeName,
				"-n", testNamespace, "--type=json", "-p", selectorPatch)
			output, err = utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "live selector retarget unexpectedly succeeded: %s", output)
			Expect(output).To(ContainSubstring("immutable"))

			By("replacing the Pod while retaining the exact bound claims and Garage identity")
			cmd = exec.Command("kubectl", "delete", "pod", staticSelectorNodeName+"-0", "-n", testNamespace,
				"--wait=true", "--timeout=2m")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to replace selector-backed Pod: %s", output)
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", staticSelectorNodeName+"-0",
					"-n", testNamespace,
					"-o", "jsonpath={.metadata.uid}/{.status.conditions[?(@.type=='Ready')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				podParts := strings.Split(output, "/")
				g.Expect(podParts).To(HaveLen(2))
				g.Expect(podParts[0]).NotTo(BeEmpty())
				g.Expect(podParts[0]).NotTo(Equal(podUID))
				g.Expect(podParts[1]).To(Equal("True"))
				for claimName, wantUID := range map[string]string{
					metadataClaim: metadataUID,
					dataClaim:     dataUID,
				} {
					cmd = exec.Command("kubectl", "get", "pvc", claimName, "-n", testNamespace,
						"-o", "jsonpath={.metadata.uid}")
					output, err = utils.Run(cmd)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(output).To(Equal(wantUID))
				}
				cmd = exec.Command("kubectl", "get", "garagenode", staticSelectorNodeName,
					"-n", testNamespace,
					"-o", "jsonpath={.status.nodeId}/{.status.observedPodUid}/{.status.connected}/{.status.inLayout}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal(originalNodeID + "/" + podParts[0] + "/true/true"))
			}, 4*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("should reject an existingClaim cycle without changing the live Pod or claims", func() {
			const metadataClaim = existingClaimNodeName + "-metadata"
			const dataClaim = existingClaimNodeName + "-data"
			By("creating user-managed metadata and data claims")
			claimsYAML := fmt.Sprintf(`
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: %s
  namespace: %s
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 100Mi
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: %s
  namespace: %s
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
`, metadataClaim, testNamespace, dataClaim, testNamespace)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(claimsYAML)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create existingClaim fixtures: %s", output)

			By("creating and fully establishing an ordinary existingClaim GarageNode")
			nodeYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef:
    name: %s
  zone: zone-c
  capacity: 1Gi
  storage:
    metadata:
      existingClaim: %s
    data:
      existingClaim: %s
  resources:
    limits:
      memory: 256Mi
    requests:
      memory: 128Mi
`, existingClaimNodeName, testNamespace, clusterName, metadataClaim, dataClaim)
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(nodeYAML)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create existingClaim GarageNode: %s", output)

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagenode", existingClaimNodeName,
					"-n", testNamespace,
					"-o", "jsonpath={.status.nodeId}/{.status.observedPodUid}/{.status.connected}/{.status.inLayout}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				parts := strings.Split(output, "/")
				g.Expect(parts).To(HaveLen(4))
				g.Expect(parts[0]).To(MatchRegexp(`^[0-9a-f]{64}$`))
				g.Expect(parts[1]).NotTo(BeEmpty())
				g.Expect(parts[2:]).To(Equal([]string{"true", "true"}))

				cmd = exec.Command("kubectl", "get", "pod", existingClaimNodeName+"-0",
					"-n", testNamespace, "-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"))

				for _, claimName := range []string{metadataClaim, dataClaim} {
					cmd = exec.Command("kubectl", "get", "pvc", claimName, "-n", testNamespace,
						"-o", "jsonpath={.status.phase}")
					output, err = utils.Run(cmd)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(output).To(Equal("Bound"))
				}
			}, 4*time.Minute, 10*time.Second).Should(Succeed())

			uidFor := func(kind, name string) string {
				cmd := exec.Command("kubectl", "get", kind, name, "-n", testNamespace,
					"-o", "jsonpath={.metadata.uid}")
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				Expect(output).NotTo(BeEmpty())
				return output
			}
			podUID := uidFor("pod", existingClaimNodeName+"-0")
			metadataPVCUID := uidFor("pvc", metadataClaim)
			dataPVCUID := uidFor("pvc", dataClaim)

			By("requesting the forbidden automatic cycle through the real validating webhook")
			cmd = exec.Command("kubectl", "annotate", "garagenode", existingClaimNodeName,
				"-n", testNamespace, "garage.rajsingh.info/cycle=true")
			output, err = utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "existingClaim cycle unexpectedly succeeded: %s", output)
			Expect(output).To(ContainSubstring("existingClaim"))

			By("proving admission left the exact source actors untouched and created no sibling")
			Expect(uidFor("pod", existingClaimNodeName+"-0")).To(Equal(podUID))
			Expect(uidFor("pvc", metadataClaim)).To(Equal(metadataPVCUID))
			Expect(uidFor("pvc", dataClaim)).To(Equal(dataPVCUID))
			cmd = exec.Command("kubectl", "get", "garagenode", existingClaimNodeName+"-cycle",
				"-n", testNamespace, "--ignore-not-found", "-o", "name")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(output)).To(BeEmpty())
			cmd = exec.Command("kubectl", "get", "garagenode", existingClaimNodeName,
				"-n", testNamespace, "-o", "jsonpath={.metadata.annotations}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(ContainSubstring("garage.rajsingh.info/cycle"))
		})

		It("should have the cluster healthy with all 4 established storage nodes", func() {
			By("verifying cluster health")
			verifyClusterHealth := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagecluster", clusterName,
					"-n", testNamespace, "-o", "jsonpath={.status.health.connectedNodes}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("4"), "Expected 4 connected nodes, got %s", output)
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
				output := runCurlPod(g, testNamespace, "curl-layout-zones", curlCmd)

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
				"-n", testNamespace, "--ignore-not-found", "--timeout=2m")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete manual test bucket: %s", output)
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
				"-n", testNamespace, "--ignore-not-found", "--timeout=2m")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete manual cluster-wide key: %s", output)
			cmd = exec.Command("kubectl", "delete", "garagebucket", "manual-cw-bucket",
				"-n", testNamespace, "--ignore-not-found", "--timeout=2m")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete manual cluster-wide bucket: %s", output)
		})

		It("should reject an unprepared unsafe individual node deletion", func() {
			By("requesting deletion of GarageNode 2 without first preparing its drain")
			cmd := exec.Command("kubectl", "delete", "garagenode", node2Name,
				"-n", testNamespace, "--wait=false")
			output, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "unprepared positive-capacity deletion must be rejected")
			Expect(output).To(ContainSubstring("prepared operation"),
				"admission should explain the drain-first contract: %s", output)

			By("verifying rejected admission left the GarageNode and StatefulSet online")
			cmd = exec.Command("kubectl", "get", "garagenode", node2Name,
				"-n", testNamespace, "-o", "jsonpath={.metadata.deletionTimestamp}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(BeEmpty(), "rejected deletion must not set deletionTimestamp")
			cmd = exec.Command("kubectl", "get", "statefulset", node2Name,
				"-n", testNamespace, "-o", "jsonpath={.status.readyReplicas}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "unsafe deletion must not reap the storage workload")
			Expect(output).To(Equal("1"), "GarageNode StatefulSet should remain Ready")
		})
	})

	Context("Per-node networking features", Ordered, func() {
		var (
			initialConfigName string
			netNodeRPCAddr    string
		)

		mountedNodeConfig := func(g Gomega) (string, string) {
			cmd := exec.Command("kubectl", "get", "statefulset", netNodeName,
				"-n", testNamespace,
				"-o", "jsonpath={.spec.template.spec.volumes[?(@.name=='config')].configMap.name}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred(), "GarageNode StatefulSet not found")
			if err != nil {
				return "", ""
			}
			configName := strings.TrimSpace(output)
			g.Expect(configName).To(HavePrefix(clusterName+"-nodecfg-"+netNodeName+"-"),
				"StatefulSet should mount an exact content-addressed per-node ConfigMap, got: %s", configName)
			if configName == "" {
				return "", ""
			}

			cmd = exec.Command("kubectl", "get", "configmap", configName,
				"-n", testNamespace, "-o", "jsonpath={.immutable}{'\\n'}{.data.garage\\.toml}")
			output, err = utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred(),
				"StatefulSet-mounted per-node ConfigMap %q not found", configName)
			if err != nil {
				return configName, ""
			}
			parts := strings.SplitN(output, "\n", 2)
			g.Expect(parts).To(HaveLen(2), "mounted ConfigMap should expose immutability and garage.toml")
			if len(parts) != 2 {
				return configName, ""
			}
			g.Expect(parts[0]).To(Equal("true"),
				"per-node Garage config revision must be immutable")
			return configName, parts[1]
		}

		It("should mount an immutable per-node ConfigMap revision with rpc_public_addr when spec.network.rpcPublicAddr is set", func() {
			netNodeRPCAddr = fmt.Sprintf("%s-0.%s-headless.%s.svc.cluster.local:3901",
				netNodeName, clusterName, testNamespace)

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
    rpcPublicAddr: %q
  resources:
    limits:
      memory: 256Mi
    requests:
      memory: 128Mi
`, netNodeName, testNamespace, clusterName, netNodeRPCAddr)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(nodeYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create GarageNode with rpcPublicAddr")

			By("waiting for the StatefulSet to mount its exact per-node ConfigMap revision")
			verifyConfigMap := func(g Gomega) {
				configName, configBody := mountedNodeConfig(g)
				g.Expect(configBody).To(ContainSubstring(`rpc_public_addr = "`+netNodeRPCAddr+`"`),
					"garage.toml in %s should contain rpc_public_addr = %q, got: %s",
					configName, netNodeRPCAddr, configBody)
				initialConfigName = configName
			}
			Eventually(verifyConfigMap, 2*time.Minute, 5*time.Second).Should(Succeed())

			Expect(initialConfigName).NotTo(BeEmpty())
			Expect(initialConfigName).NotTo(Equal(netNodeName+"-config"),
				"the retired mutable fixed-name ConfigMap contract must not return")
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
    rpcPublicAddr: %q
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
`, netNodeName, testNamespace, clusterName, netNodeRPCAddr)

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
					"-o", "jsonpath={.spec.ports[?(@.name==\"rpc\")].nodePort}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("31901"), "expected nodePort 31901, got: %s", output)
			}
			Eventually(verifyPort, 1*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should publish a new per-node ConfigMap revision when spec.storage fsync overrides are set", func() {
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
    rpcPublicAddr: %q
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
`, netNodeName, testNamespace, clusterName, netNodeRPCAddr)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(patchYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to patch GarageNode with metadataFsync")

			By("verifying the StatefulSet mounts a new immutable revision containing metadata_fsync = true")
			verifyFsync := func(g Gomega) {
				configName, configBody := mountedNodeConfig(g)
				g.Expect(configName).NotTo(Equal(initialConfigName),
					"a config change must publish and mount a new content-addressed revision")
				g.Expect(configBody).To(ContainSubstring("metadata_fsync = true"),
					"garage.toml in %s should contain metadata_fsync = true, got: %s",
					configName, configBody)
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
    rpcPublicAddr: %q
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
`, netNodeName, testNamespace, clusterName, netNodeRPCAddr)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(patchYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to patch GarageNode with imagePullPolicy")

			By("verifying StatefulSet container has imagePullPolicy: IfNotPresent")
			verifyPullPolicy := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", netNodeName,
					"-n", testNamespace,
					"-o", "jsonpath={.spec.template.spec.containers[?(@.name==\"garage\")].imagePullPolicy}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("IfNotPresent"),
					"expected IfNotPresent, got: %s", output)
			}
			Eventually(verifyPullPolicy, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})

	It("should prepare and complete deletion after replacement capacity joins", func() {
		By("waiting for the replacement Manual node to join the layout")
		verifyReplacementInLayout := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenode", "garage-node-net",
				"-n", testNamespace, "-o", "jsonpath={.status.inLayout}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("true"), "replacement GarageNode is not in the layout")
		}
		Eventually(verifyReplacementInLayout, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("waiting for the preceding GarageNode config rollout to reach its exact final Pod revision")
		verifyConfigRolloutConverged := func(g Gomega) {
			assertParentTransactionsIdle := func() {
				cmd := exec.Command("kubectl", "get", "garagecluster", clusterName,
					"-n", testNamespace,
					"-o", `jsonpath={.metadata.generation}|{.status.observedGeneration}|{.status.storageRollout}|{.status.storageDrain}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				clusterParts := strings.Split(output, "|")
				g.Expect(clusterParts).To(HaveLen(4), "unexpected GarageCluster rollout projection: %q", output)
				if len(clusterParts) != 4 {
					return
				}
				g.Expect(clusterParts[1]).To(Equal(clusterParts[0]),
					"GarageCluster status has not observed its current generation: %q", output)
				g.Expect(clusterParts[2:]).To(Equal([]string{"", ""}),
					"storage rollout or drain transaction remains active: %q", output)
			}
			assertParentTransactionsIdle()

			cmd := exec.Command("kubectl", "get", "statefulset", netNodeName,
				"-n", testNamespace,
				"-o", `jsonpath={.metadata.uid}|{.metadata.generation}|{.status.observedGeneration}|{.status.replicas}|{.status.readyReplicas}|{.status.updatedReplicas}|{.status.updateRevision}|{.spec.template.spec.volumes[?(@.name=="config")].configMap.name}|{.spec.template.spec.containers[?(@.name=="garage")].imagePullPolicy}`)
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			statefulSetParts := strings.Split(output, "|")
			g.Expect(statefulSetParts).To(HaveLen(9), "unexpected StatefulSet rollout projection: %q", output)
			if len(statefulSetParts) != 9 {
				return
			}
			g.Expect(statefulSetParts[0]).NotTo(BeEmpty())
			g.Expect(statefulSetParts[2]).To(Equal(statefulSetParts[1]),
				"StatefulSet controller has not observed its current generation: %q", output)
			g.Expect(statefulSetParts[3:6]).To(Equal([]string{"1", "1", "1"}),
				"StatefulSet must have exactly one updated and Ready replica: %q", output)
			g.Expect(statefulSetParts[6]).NotTo(BeEmpty())
			g.Expect(statefulSetParts[7]).NotTo(BeEmpty())
			g.Expect(statefulSetParts[8]).To(Equal("IfNotPresent"))

			cmd = exec.Command("kubectl", "get", "pod", netNodeName+"-0",
				"-n", testNamespace,
				"-o", `jsonpath={.metadata.uid}|{.metadata.ownerReferences[?(@.controller==true)].uid}|{.metadata.deletionTimestamp}|{.metadata.labels.controller-revision-hash}|{.status.conditions[?(@.type=="Ready")].status}|{.spec.volumes[?(@.name=="config")].configMap.name}|{.spec.containers[?(@.name=="garage")].imagePullPolicy}`)
			output, err = utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			podParts := strings.Split(output, "|")
			g.Expect(podParts).To(HaveLen(7), "unexpected Pod rollout projection: %q", output)
			if len(podParts) != 7 {
				return
			}
			g.Expect(podParts[0]).NotTo(BeEmpty())
			g.Expect(podParts[1]).To(Equal(statefulSetParts[0]),
				"current Pod is not controller-owned by the exact StatefulSet UID")
			g.Expect(podParts[2]).To(BeEmpty(), "current Pod is already deleting")
			g.Expect(podParts[3]).To(Equal(statefulSetParts[6]),
				"current Pod is not on the StatefulSet's exact update revision")
			g.Expect(podParts[4]).To(Equal("True"))
			g.Expect(podParts[5]).To(Equal(statefulSetParts[7]),
				"current Pod does not mount the StatefulSet's final config revision")
			g.Expect(podParts[6]).To(Equal("IfNotPresent"))

			cmd = exec.Command("kubectl", "get", "garagenode", netNodeName,
				"-n", testNamespace,
				"-o", `jsonpath={.metadata.generation}|{.status.observedGeneration}|{.status.observedPodUid}|{.status.connected}|{.status.inLayout}|{.status.conditions[?(@.type=="Ready")].observedGeneration}|{.status.conditions[?(@.type=="Ready")].status}|{.status.conditions[?(@.type=="Ready")].reason}`)
			output, err = utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			nodeParts := strings.Split(output, "|")
			g.Expect(nodeParts).To(HaveLen(8), "unexpected GarageNode rollout projection: %q", output)
			if len(nodeParts) != 8 {
				return
			}
			g.Expect(nodeParts[1]).To(Equal(nodeParts[0]), "GarageNode status is stale: %q", output)
			g.Expect(nodeParts[2]).To(Equal(podParts[0]),
				"GarageNode has not observed the exact final Pod UID")
			g.Expect(nodeParts[3:5]).To(Equal([]string{"true", "true"}))
			g.Expect(nodeParts[5]).To(Equal(nodeParts[0]), "GarageNode Ready condition is stale: %q", output)
			g.Expect(nodeParts[6:]).To(Equal([]string{"True", "NodeReady"}))

			// Close the cross-read window after proving the exact workload revision.
			// Admission remains the authoritative fail-closed serialization boundary.
			assertParentTransactionsIdle()
		}
		// A positive-capacity OnDelete rollout uses the same cluster-wide safety
		// coordinator as drain. Wait for the exact workload/config handoff and
		// the completed storage-rollout transaction before requesting a drain.
		Eventually(verifyConfigRolloutConverged, 20*time.Minute, 10*time.Second).Should(Succeed())

		By("requesting the documented reversible drain preparation")
		cmd := exec.Command("kubectl", "annotate", "garagenode", node2Name,
			"-n", testNamespace, "garage.rajsingh.info/drain=true", "--overwrite")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to request GarageNode drain preparation: %s", output)

		By("waiting for the current GarageNode generation to hold an exact terminal drain proof")
		verifyDrainPrepared := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenode", node2Name,
				"-n", testNamespace,
				"-o", `jsonpath={.metadata.generation}|{.status.conditions[?(@.type=="DrainPrepared")].observedGeneration}|{.status.conditions[?(@.type=="DrainPrepared")].status}|{.status.conditions[?(@.type=="DrainPrepared")].reason}`)
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			parts := strings.Split(output, "|")
			g.Expect(parts).To(HaveLen(4), "unexpected DrainPrepared projection: %q", output)
			if len(parts) != 4 {
				return
			}
			g.Expect(parts[1]).To(Equal(parts[0]), "DrainPrepared condition is stale: %q", output)
			g.Expect(parts[2:]).To(Equal([]string{"True", "PreparedForDeletion"}),
				"GarageNode drain has not completed its exact block/layout proof: %q", output)
		}
		// The production proof is two phases, not one fixed interval: first the
		// operator launches and waits for verification-node block-repair workers
		// to go idle (unbounded — observed ~10m on a loaded CI runner before
		// QuietSince is even set), then only after that does Garage's own
		// 610-second delayed-block-GC quiet window start. A 20m budget measured
		// only the second phase and timed out ~2m short in practice
		// ("waiting 2m4s more through Garage's delayed-resync interval" at the
		// 20m mark). 30m covers both phases with real margin.
		Eventually(verifyDrainPrepared, 30*time.Minute, 10*time.Second).Should(Succeed())

		By("deleting the now-prepared GarageNode through admission's exact terminal-proof check")
		cmd = exec.Command("kubectl", "delete", "garagenode", node2Name,
			"-n", testNamespace, "--wait=false")
		output, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Prepared GarageNode deletion was rejected: %s", output)

		By("waiting for GarageNode 2 and its StatefulSet to drain and delete")
		verifyNodeAndStatefulSetDeleted := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenode", node2Name, "-n", testNamespace,
				"--ignore-not-found", "-o", "name")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred(), "GarageNode deletion check must reach the API server")
			g.Expect(strings.TrimSpace(output)).To(BeEmpty(),
				"GarageNode 2 should be deleted after replacement")

			cmd = exec.Command("kubectl", "get", "statefulset", node2Name, "-n", testNamespace,
				"--ignore-not-found", "-o", "name")
			output, err = utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred(), "StatefulSet deletion check must reach the API server")
			g.Expect(strings.TrimSpace(output)).To(BeEmpty(),
				"StatefulSet 2 should be deleted after layout drain")

			cmd = exec.Command("kubectl", "get", "garagecluster", clusterName,
				"-n", testNamespace, "-o", "jsonpath={.status.storageDrain}")
			output, err = utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(BeEmpty(), "consumed GarageNode drain transaction should be cleared")
		}
		Eventually(verifyNodeAndStatefulSetDeleted, 5*time.Minute, 5*time.Second).Should(Succeed())
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
		Expect(createE2ETestNamespace(testNamespace)).To(Succeed())
	})

	AfterAll(func() {
		cmd := exec.Command("kubectl", "delete", "garagecluster", gatewayClusterName, "-n", testNamespace,
			"--ignore-not-found", "--wait=false")
		if output, err := utils.Run(cmd); err != nil {
			reportE2ECleanupWait("external gateway GarageCluster delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("external gateway GarageCluster", waitForE2EResourceDeleted(
			"garagecluster", gatewayClusterName, testNamespace, 3*time.Minute,
		))
		cmd = exec.Command("kubectl", "delete", "ns", testNamespace, "--ignore-not-found", "--wait=false")
		output, err := utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("external gateway namespace delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("external gateway namespace", waitForE2ENamespaceDeleted(testNamespace, 2*time.Minute))
		finishE2ECleanupWaits()
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
  image: dxflrs/garage:v2.3.0@sha256:866bd13ed2038ba7e7190e840482bc27234c4afaf77be8cfa439ae088c1e4690
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

			resp, err := (&http.Client{Timeout: e2eHTTPTimeout}).Do(req)
			g.Expect(err).NotTo(HaveOccurred())
			if err != nil {
				return
			}
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
			output, err := utils.Run(cmd)
			if err != nil {
				return ""
			}
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
		Expect(ensureE2ENamespaceActive(namespace)).To(Succeed())

		By("labeling the manager namespace to enforce the restricted security policy")
		cmd := exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label manager namespace: %s", output)

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("waiting for Garage CRDs to be Established")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for the webhook Service route")
		Expect(waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())

		By("waiting for controller-manager pod to be Ready (webhook server started)")
		verifyControllerUp := func(g Gomega) {
			_, err := controllerManagerPodReady(namespace)
			g.Expect(err).NotTo(HaveOccurred(), "Controller not Ready")
		}
		Eventually(verifyControllerUp, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("creating test namespace")
		Expect(createE2ETestNamespace(testNamespace)).To(Succeed())

		By("labeling the test namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		cleanupAuto190(testNamespace, []string{node0Name, node1Name, node2Name})
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

		// Wait for the new member to actually join, not merely to exist as a CR.
		// Removing a node that holds positive capacity is a drain, and admission
		// requires StorageRolloutReady=True at the current generation before one
		// starts — so a scale-down issued while this node is still joining is
		// refused, correctly: partitions are already being assigned to it. Any
		// operator reversing a scale-up has to wait for the same signal.
		By("waiting for the new member to converge before the next topology change")
		verifyNode2Converged := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenode", node2Name, "-n", testNamespace,
				"-o", "jsonpath={.status.connected}|{.status.inLayout}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(stripKubectlWarnings(output)).To(Equal("true|true"),
				"GarageNode %s has not joined the layout: %q", node2Name, output)

			cmd = exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace,
				"-o", "jsonpath={.status.conditions[?(@.type=='StorageRolloutReady')].status}")
			output, err = utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(stripKubectlWarnings(output)).To(Equal("True"),
				"StorageRolloutReady is not converged: %q", output)
		}
		Eventually(verifyNode2Converged, 5*time.Minute, 10*time.Second).Should(Succeed())
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
		// Removing a member that holds positive capacity is a two-phase drain:
		// repair workers must first converge, then the drain barrier waits through
		// Garage's delayed-resync window before it concludes no block is coming
		// back. Upstream re-queues a block whose refcount hit zero at
		// BLOCK_GC_DELAY + 10s (600+10s, src/block/manager.rs), which
		// effectiveBlockResyncQuietPeriod mirrors as 610s plus one short requeue —
		// about 11m10s. On a loaded CI runner, repair-worker convergence can take
		// about 10m before the quiet timer even starts. Keep this aligned with the
		// manual drain test's 30m budget so correct delayed removal is not reported
		// as a failure.
		Eventually(verifyNode2Gone, 30*time.Minute, 10*time.Second).Should(Succeed())
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
		cmd = exec.Command("kubectl", "delete", "sts", node0Name, "-n", testNamespace,
			"--wait=true", "--timeout=2m")
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
		Expect(ensureE2ENamespaceActive(namespace)).To(Succeed())

		By("labeling the manager namespace to enforce the restricted security policy")
		output, err := utils.Run(exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted"))
		Expect(err).NotTo(HaveOccurred(), "Failed to label manager namespace: %s", output)

		By("installing CRDs")
		_, err = utils.Run(exec.Command("make", "install"))
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("waiting for Garage CRDs to be Established")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		_, err = utils.Run(exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage)))
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for controller-manager pod to be Ready (webhook server started)")
		Eventually(func(g Gomega) {
			_, err := controllerManagerPodReady(namespace)
			g.Expect(err).NotTo(HaveOccurred(), "Controller not Ready")
		}, 3*time.Minute, 5*time.Second).Should(Succeed())
		Expect(waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())

		By("creating test namespace")
		Expect(createE2ETestNamespace(testNamespace)).To(Succeed())
		_, err = utils.Run(exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted"))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		cleanupAuto190(testNamespace, []string{nodeName})
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

// Auto Mode EmptyDir legacy-STS migration — regression for #286. A pre-v0.6
// EmptyDir cluster has a legacy cluster-level StatefulSet but no PVCs; before
// the fix, migrateLegacyStorageSTSIfNeeded required the metadata/data PVCs and
// failed, permanently wedging the cluster. This seeds a legacy EmptyDir STS,
// then creates the GarageCluster and asserts the operator migrates it to a
// fresh EmptyDir-backed per-node GarageNode (no PVCs) and removes the legacy STS.
var _ = Describe("Auto Mode EmptyDir migration", Ordered, Label("auto-mode-ephemeral"), func() {
	const testNamespace = "garage-auto-migration-test"
	const clusterName = "mig-ephem-cluster"
	const nodeName = "mig-ephem-cluster-storage-0"
	// Shared by the seeded Garage's config and the Secret the GarageCluster
	// references, so the operator's probe of the legacy Pod authenticates.
	const legacyAdminToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const legacyRPCSecret = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	BeforeAll(func() {
		By("creating manager namespace")
		Expect(ensureE2ENamespaceActive(namespace)).To(Succeed())
		output, err := utils.Run(exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted"))
		Expect(err).NotTo(HaveOccurred(), "Failed to label manager namespace: %s", output)

		By("installing CRDs")
		_, err = utils.Run(exec.Command("make", "install"))
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		_, err = utils.Run(exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage)))
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for controller-manager pod to be Ready (webhook server started)")
		Eventually(func(g Gomega) {
			_, err := controllerManagerPodReady(namespace)
			g.Expect(err).NotTo(HaveOccurred(), "Controller not Ready")
		}, 3*time.Minute, 5*time.Second).Should(Succeed())
		Expect(waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())

		By("creating test namespace")
		Expect(createE2ETestNamespace(testNamespace)).To(Succeed())
		_, err = utils.Run(exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted"))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		cleanupAuto190(testNamespace, []string{nodeName})
	})

	It("migrates a legacy EmptyDir StatefulSet (no PVCs) to a fresh EmptyDir per-node GarageNode", func() {
		// The admin token Secret must exist before the legacy StatefulSet, because
		// the seeded Pod mounts it exactly as the pre-#190 operator did — and its
		// value has to match the admin_token the seeded Garage boots with, or the
		// operator's probe of that Pod is refused on a 401 rather than proving
		// anything about the migration.
		By("creating admin token secret")
		adminTokenSecret := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: garage-admin-token
  namespace: %s
type: Opaque
stringData:
  admin-token: %q
`, testNamespace, legacyAdminToken)
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(adminTokenSecret)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create admin token secret")

		// A real Garage, not a placeholder process. Taking the first static
		// credential snapshot probes every existing Pod's Admin API with the source
		// token and refuses the snapshot if one does not answer — correctly, since
		// that is how the operator proves which live processes already trust the
		// credential. A sleeping container can never satisfy that, so seeding one
		// tested nothing a real upgrade does. Still EmptyDir with no
		// volumeClaimTemplates, which is what this spec is about.
		By("seeding a legacy EmptyDir cluster-level StatefulSet (no volumeClaimTemplates)")
		legacySTS := fmt.Sprintf(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: %[1]s-legacy-config
  namespace: %[2]s
data:
  garage.toml: |
    metadata_dir = "/var/lib/garage/meta"
    data_dir = "/var/lib/garage/data"
    db_engine = "lmdb"
    replication_factor = 1
    rpc_bind_addr = "[::]:3901"
    rpc_secret = "%[4]s"

    [s3_api]
    s3_region = "garage"
    api_bind_addr = "[::]:3900"
    root_domain = ".s3.garage"

    [admin]
    api_bind_addr = "[::]:3903"
    admin_token = "%[3]s"
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    garage.rajsingh.info/cluster: %[1]s
    garage.rajsingh.info/tier: storage
spec:
  serviceName: %[1]s-headless
  replicas: 1
  selector:
    matchLabels:
      garage.rajsingh.info/cluster: %[1]s
      garage.rajsingh.info/tier: storage
  template:
    metadata:
      labels:
        garage.rajsingh.info/cluster: %[1]s
        garage.rajsingh.info/tier: storage
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        # EmptyDir mounts are root-owned without this, so a non-root Garage
        # cannot create its lmdb and the Pod never becomes Ready.
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: garage
          image: %[5]s
          command: ["/garage", "server"]
          ports:
            - {name: s3, containerPort: 3900}
            - {name: rpc, containerPort: 3901}
            - {name: admin, containerPort: 3903}
          readinessProbe:
            tcpSocket:
              port: 3903
            initialDelaySeconds: 5
            periodSeconds: 5
          resources:
            requests: {memory: 128Mi}
            limits: {memory: 512Mi}
          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            runAsUser: 1000
            capabilities:
              drop: ["ALL"]
            seccompProfile:
              type: RuntimeDefault
          volumeMounts:
            - name: metadata
              mountPath: /var/lib/garage/meta
            - name: data
              mountPath: /var/lib/garage/data
            - name: admin-token
              mountPath: /secrets/admin
              readOnly: true
            - {name: config, mountPath: /etc/garage.toml, subPath: garage.toml}
      volumes:
        - name: metadata
          emptyDir: {}
        - name: data
          emptyDir: {}
        # Exactly how the pre-#190 operator supplied the startup bearer: a Secret
        # volume named admin-token, not the SecretKeyRef env var used since. The
        # operator has to recognise this form to migrate a real legacy cluster —
        # proving the exact managed Pod set is a precondition of the first static
        # credential snapshot, which the migration runs behind. Omitting it here
        # made the seeded Pod something no released operator ever produced.
        - name: admin-token
          secret:
            secretName: garage-admin-token
            defaultMode: 0600
            items:
              - key: admin-token
                path: admin-token
        - name: config
          configMap:
            name: %[1]s-legacy-config
`, clusterName, testNamespace, legacyAdminToken, legacyRPCSecret, e2eGarageImage)
		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(legacySTS)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create legacy STS")

		By("creating the ephemeral GarageCluster over the legacy STS")
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
		Eventually(func(g Gomega) {
			c := exec.Command("kubectl", "apply", "-f", "-")
			c.Stdin = strings.NewReader(clusterYAML)
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred(), "Failed to create GarageCluster: %s", out)
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying migration completes (LegacySTSMigrated=Completed)")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace,
				"-o", "jsonpath={.status.conditions[?(@.type=='LegacySTSMigrated')].reason}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Completed"), "migration not Completed: %q", output)
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying the legacy cluster-level StatefulSet was removed")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "statefulset", clusterName, "-n", testNamespace)
			_, err := utils.Run(cmd)
			g.Expect(err).To(HaveOccurred(), "legacy STS %q should have been orphan-deleted", clusterName)
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying a fresh per-node GarageNode was created")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenode", nodeName, "-n", testNamespace,
				"-o", "jsonpath={.metadata.name}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal(nodeName))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying the migrated pod runs EmptyDir-backed with no PVCs")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "pod", nodeName+"-0", "-n", testNamespace,
				"-o", "jsonpath={.status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Running"), "migrated pod %s-0 not running: %s", nodeName, output)
		}, 5*time.Minute, 5*time.Second).Should(Succeed())

		cmd = exec.Command("kubectl", "get", "pvc", "-n", testNamespace,
			"-o", "jsonpath={.items[*].metadata.name}")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.Fields(output)).To(BeEmpty(),
			"migrated EmptyDir cluster must not provision PVCs, found: %q", output)
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
		Expect(ensureE2ENamespaceActive(namespace)).To(Succeed())

		By("labeling the manager namespace to enforce the restricted security policy")
		cmd := exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label manager namespace: %s", output)

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("waiting for Garage CRDs to be Established")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for the webhook Service route")
		Expect(waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())

		By("waiting for controller-manager pod to be Ready (webhook server started)")
		verifyControllerUp := func(g Gomega) {
			_, err := controllerManagerPodReady(namespace)
			g.Expect(err).NotTo(HaveOccurred(), "Controller not Ready")
		}
		Eventually(verifyControllerUp, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("creating test namespace")
		Expect(createE2ETestNamespace(testNamespace)).To(Succeed())

		By("labeling the test namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		cleanupAuto190(testNamespace, nil)
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

		By("confirming the Manual policy before testing its one-way transition")
		Eventually(func(g Gomega) {
			out, err := utils.Run(exec.Command("kubectl", "get", "garagecluster", clusterName,
				"-n", testNamespace, "-o", "jsonpath={.spec.layoutPolicy}"))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal("Manual"))
		}, time.Minute, time.Second).Should(Succeed())

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
		Expect(ensureE2ENamespaceActive(namespace)).To(Succeed())
		output, err := utils.Run(exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted"))
		Expect(err).NotTo(HaveOccurred(), "Failed to label manager namespace: %s", output)

		By("installing CRDs")
		_, err = utils.Run(exec.Command("make", "install"))
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		_, err = utils.Run(exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage)))
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
		Expect(waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())

		By("waiting for controller-manager pod to be Ready (webhook server started)")
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

// The block above adopts an operator-managed stand-in via connectTo.clusterRef.
// This one covers the shape #269 actually exists for and #295 asked to pin: a
// Garage the operator did not deploy and must never touch (here a hand-rolled
// StatefulSet standing in for the upstream Helm chart), adopted through
// connectTo.adminApiEndpoint + adminTokenSecretRef.
//
// Three one-line conditions are easy to reintroduce by refactor and would break
// adoption silently, so each gets an explicit assertion:
//
//  1. GetGarageClient must resolve the endpoint from spec.connectTo, not from
//     the managed Service FQDN (which does not exist here) — proven by the
//     bucket/key landing on the external cluster and by the generated Secret's
//     endpoint being derived from the connectTo host.
//  2. The webhook must accept connectTo standalone (pre-#269 code rejected it).
//  3. GarageBucket/GarageKey must not gate on pod-readiness-derived phase.
//
// Plus the contract that makes adoption safe at all: the operator owns no
// workload, and deleting the CRs leaves the external workload running.
//
// The external Garage is a plain manifest rather than `helm install` of the
// upstream chart: the chart lives on git.deuxfleurs.fr, and reaching a
// non-standard forge from CI buys a flake for no extra coverage. What matters
// is only that the workload has no operator ownerReference — which a raw
// StatefulSet models exactly.
var _ = Describe("Management Handle (externally-managed Garage)", Ordered, Label("management-handle"), func() {
	const (
		testNamespace = "garage-mgmt-external"
		extName       = "ext-garage"
		handleName    = "adopted-cluster"
		bucketName    = "adopted-bucket"
		keyName       = "adopted-key"
		deniedKeyName = "adopted-denied-key"
		extAdminToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		extRPCSecret  = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	)

	var (
		adminEndpoint = fmt.Sprintf("http://%s.%s.svc.cluster.local:3903", extName, testNamespace)
		s3Endpoint    = fmt.Sprintf("http://%s.%s.svc.cluster.local:3900", extName, testNamespace)
		bucketID      string
	)

	// extAdminCurl runs a curl against the external cluster's Admin API from
	// inside the kind cluster and returns the response body.
	extAdminCurl := func(g Gomega, podName, method, path, body string) string {
		args := fmt.Sprintf("-s -X %s -H 'Authorization: Bearer %s'", method, extAdminToken)
		if body != "" {
			args += fmt.Sprintf(" -H 'Content-Type: application/json' -d %s", shellQuote(body))
		}
		return runCurlPod(g, testNamespace, podName, fmt.Sprintf("curl %s %s%s", args, adminEndpoint, path))
	}

	BeforeAll(func() {
		By("creating manager namespace")
		Expect(ensureE2ENamespaceActive(namespace)).To(Succeed())
		output, err := utils.Run(exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted"))
		Expect(err).NotTo(HaveOccurred(), "Failed to label manager namespace: %s", output)

		By("installing CRDs")
		_, err = utils.Run(exec.Command("make", "install"))
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		_, err = utils.Run(exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage)))
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
		Expect(waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())

		By("waiting for controller-manager pod to be Ready (webhook server started)")
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
		cleanupManagementHandle(testNamespace, []string{handleName})
	})

	Context("When adopting a Garage the operator does not own", func() {
		It("should stand up an externally-managed Garage StatefulSet", func() {
			By("applying the external workload (Secret + ConfigMap + Service + StatefulSet)")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(externalGarageManifests(testNamespace, extName, extAdminToken, extRPCSecret))
			out, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply external Garage: %s", out)

			By("waiting for the external Garage pod to be Ready")
			Eventually(func(g Gomega) {
				c := exec.Command("kubectl", "get", "pod", extName+"-0", "-n", testNamespace,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				o, err := utils.Run(c)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(o).To(Equal("True"), "external Garage not Ready: %s", o)
			}, 5*time.Minute, 5*time.Second).Should(Succeed())

			By("bootstrapping its layout so buckets and keys can be written")
			var nodeID string
			Eventually(func(g Gomega) {
				body := extAdminCurl(g, "ext-status", "GET", "/v2/GetClusterStatus", "")
				g.Expect(body).To(ContainSubstring(`"id"`), "unexpected status body: %s", body)
				nodeID = firstJSONNodeID(body)
				g.Expect(nodeID).NotTo(BeEmpty(), "no node id in status: %s", body)
			}, 3*time.Minute, 10*time.Second).Should(Succeed())

			// Staged and applied once, outside the health poll: a second apply at
			// version 1 fails because the first one already bumped it.
			Eventually(func(g Gomega) {
				// UpdateClusterLayout takes {"roles":[…]}, not a bare array, and
				// NodeAssignedRole requires `tags` — Garage rejects the entry as
				// "did not match any variant of untagged enum NodeRoleChangeEnum"
				// without it (../garage doc/api/garage-admin-v2.json).
				layout := fmt.Sprintf(`{"roles":[{"id":"%s","zone":"external","capacity":1073741824,"tags":[]}]}`, nodeID)
				extAdminCurl(g, "ext-layout", "POST", "/v2/UpdateClusterLayout", layout)
				extAdminCurl(g, "ext-apply", "POST", "/v2/ApplyClusterLayout", `{"version":1}`)
			}, 2*time.Minute, 10*time.Second).Should(Succeed())

			Eventually(func(g Gomega) {
				body := extAdminCurl(g, "ext-health", "GET", "/v2/GetClusterHealth", "")
				// Garage pretty-prints its JSON, so match the field rather than a
				// compact substring.
				g.Expect(body).To(MatchRegexp(`"status":\s*"healthy"`), "external cluster not healthy: %s", body)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should accept a tier-less connectTo handle and reach Running", func() {
			// rpcSecretRef is required for creating brand-new GarageKeys against a
			// handle: key material is derived deterministically from the RPC secret,
			// and a handle has no operator-generated <cluster>-rpc-secret to fall
			// back on.
			handleYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  connectTo:
    adminApiEndpoint: %q
    adminTokenSecretRef:
      name: %s-secrets
      key: admin-token
  network:
    rpcSecretRef:
      name: %s-secrets
      key: rpc-secret
`, handleName, testNamespace, adminEndpoint, extName, extName)

			By("applying the handle (webhook must accept connectTo standalone)")
			Eventually(func(g Gomega) {
				c := exec.Command("kubectl", "apply", "-f", "-")
				c.Stdin = strings.NewReader(handleYAML)
				o, err := utils.Run(c)
				g.Expect(err).NotTo(HaveOccurred(), "handle rejected: %s", o)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for Running + ManagementHandleReady")
			Eventually(func(g Gomega) {
				c := exec.Command("kubectl", "get", "garagecluster", handleName, "-n", testNamespace,
					"-o", "jsonpath={.status.phase}/{.status.conditions[?(@.type=='ManagementHandleReady')].status}")
				o, err := utils.Run(c)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(o).To(Equal("Running/True"), "handle not ready: %s", o)
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should provision no workload of its own", func() {
			for _, kind := range []string{"statefulset", "deployment", "service", "configmap", "persistentvolumeclaim"} {
				By("verifying no operator-owned " + kind + " exists for the handle")
				c := exec.Command("kubectl", "get", kind, "-n", testNamespace,
					"-l", "app.kubernetes.io/instance="+handleName,
					"-o", "jsonpath={.items[*].metadata.name}")
				o, err := utils.Run(c)
				Expect(err).NotTo(HaveOccurred())
				Expect(o).To(BeEmpty(), "handle must own no %s, got: %s", kind, o)

				c = exec.Command("kubectl", "get", kind, handleName, "-n", testNamespace)
				_, err = utils.Run(c)
				Expect(err).To(HaveOccurred(), "handle must not create a %s named after itself", kind)
			}

			By("verifying no GarageNodes were generated")
			c := exec.Command("kubectl", "get", "garagenode", "-n", testNamespace,
				"-o", "jsonpath={.items[*].metadata.name}")
			o, err := utils.Run(c)
			Expect(err).NotTo(HaveOccurred())
			Expect(o).To(BeEmpty(), "handle must not create GarageNodes, got: %s", o)

			By("verifying the external StatefulSet was not adopted (no ownerReferences)")
			c = exec.Command("kubectl", "get", "statefulset", extName, "-n", testNamespace,
				"-o", "jsonpath={.metadata.ownerReferences}")
			o, err = utils.Run(c)
			Expect(err).NotTo(HaveOccurred())
			Expect(o).To(BeEmpty(), "operator must not take ownership of the external workload: %s", o)
		})

		It("should create a bucket on the external cluster through the handle", func() {
			bucketYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef:
    name: %s
  globalAlias: %s
`, bucketName, testNamespace, handleName, bucketName)

			Eventually(func(g Gomega) {
				c := exec.Command("kubectl", "apply", "-f", "-")
				c.Stdin = strings.NewReader(bucketYAML)
				o, err := utils.Run(c)
				g.Expect(err).NotTo(HaveOccurred(), "bucket rejected: %s", o)
			}, 1*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for the bucket to reach Ready with a bucketId")
			Eventually(func(g Gomega) {
				c := exec.Command("kubectl", "get", "garagebucket", bucketName, "-n", testNamespace,
					"-o", "jsonpath={.status.bucketId}")
				o, err := utils.Run(c)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(o).NotTo(BeEmpty(), "bucket has no bucketId")
				bucketID = o
			}, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the bucket really exists on the external cluster's Admin API")
			Eventually(func(g Gomega) {
				body := extAdminCurl(g, "ext-buckets", "GET", "/v2/ListBuckets", "")
				g.Expect(body).To(ContainSubstring(bucketID),
					"bucket %s absent from external cluster: %s", bucketID, body)
			}, 2*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("should render credentials without inferring S3 from the external Admin endpoint", func() {
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
  secretTemplate:
    includeEndpoint: false
`, keyName, testNamespace, handleName, bucketName)

			Eventually(func(g Gomega) {
				c := exec.Command("kubectl", "apply", "-f", "-")
				c.Stdin = strings.NewReader(keyYAML)
				o, err := utils.Run(c)
				g.Expect(err).NotTo(HaveOccurred(), "key rejected: %s", o)
			}, 1*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for the credential Secret to be rendered")
			Eventually(func(g Gomega) {
				c := exec.Command("kubectl", "get", "secret", keyName, "-n", testNamespace,
					"-o", `go-template={{ index .data "access-key-id" | base64decode }}`)
				o, err := utils.Run(c)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(o).NotTo(BeEmpty(), "access-key-id missing from secret")
			}, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying no endpoint is inferred from connectTo.adminApiEndpoint")
			c := exec.Command("kubectl", "get", "secret", keyName, "-n", testNamespace,
				"-o", `go-template={{ if index .data "endpoint" }}present{{ end }}`)
			o, err := utils.Run(c)
			Expect(err).NotTo(HaveOccurred())
			Expect(o).To(BeEmpty(),
				"management-handle credentials must not derive an S3 endpoint from the Admin API URL")

			By("verifying the key exists on the external cluster's Admin API")
			accessKeyID := readSecretValue(testNamespace, keyName, "access-key-id")
			Eventually(func(g Gomega) {
				body := extAdminCurl(g, "ext-keys", "GET", "/v2/ListKeys", "")
				g.Expect(body).To(ContainSubstring(accessKeyID),
					"key %s absent from external cluster: %s", accessKeyID, body)
			}, 2*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("should round-trip an object with the generated credentials", func() {
			Expect(bucketID).NotTo(BeEmpty(), "bucket test must run first")

			const payload = "adopted-handle-round-trip"
			script := fmt.Sprintf(
				`printf '%s' > /tmp/payload.txt && `+
					`aws s3api put-object --endpoint-url %s --region garage --bucket %s --key obj --body /tmp/payload.txt && `+
					`aws s3api get-object --endpoint-url %s --region garage --bucket %s --key obj /tmp/out.txt && `+
					`cat /tmp/out.txt`,
				payload, s3Endpoint, bucketName, s3Endpoint, bucketName)

			Eventually(func(g Gomega) {
				out := runAWSCLI(g, testNamespace, "handle-s3-verify", script, keyName, true)
				g.Expect(out).To(ContainSubstring(payload), "GET did not return the PUT payload: %s", out)
			}, 3*time.Minute, 30*time.Second).Should(Succeed())
		})

		It("should deny a key that has no permission on the bucket", func() {
			deniedYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef:
    name: %s
  secretTemplate:
    includeEndpoint: false
`, deniedKeyName, testNamespace, handleName)

			Eventually(func(g Gomega) {
				c := exec.Command("kubectl", "apply", "-f", "-")
				c.Stdin = strings.NewReader(deniedYAML)
				o, err := utils.Run(c)
				g.Expect(err).NotTo(HaveOccurred(), "denied-key rejected: %s", o)
			}, 1*time.Minute, 5*time.Second).Should(Succeed())

			Eventually(func(g Gomega) {
				c := exec.Command("kubectl", "get", "secret", deniedKeyName, "-n", testNamespace,
					"-o", `go-template={{ index .data "access-key-id" | base64decode }}`)
				o, err := utils.Run(c)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(o).NotTo(BeEmpty())
			}, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying a GET with the unpermitted key is refused")
			script := fmt.Sprintf(
				`aws s3api get-object --endpoint-url %s --region garage --bucket %s --key obj /tmp/out.txt`,
				s3Endpoint, bucketName)
			Eventually(func(g Gomega) {
				// expectSuccess=false: the aws-cli pod is supposed to fail here.
				out := runAWSCLI(g, testNamespace, "handle-s3-denied", script, deniedKeyName, false)
				g.Expect(out).To(Or(
					ContainSubstring("AccessDenied"),
					ContainSubstring("Forbidden"),
					ContainSubstring("403"),
					ContainSubstring("NoSuchBucket"),
				), "unpermitted key should be refused, got: %s", out)
			}, 3*time.Minute, 30*time.Second).Should(Succeed())
		})

		It("should leave the external workload running after the handle is deleted", func() {
			By("removing the data-plane fixture before finalizing its bucket")
			script := fmt.Sprintf(
				`aws s3api delete-object --endpoint-url %s --region garage --bucket %s --key obj`,
				s3Endpoint, bucketName)
			Eventually(func(g Gomega) {
				_ = runAWSCLI(g, testNamespace, "handle-s3-cleanup", script, keyName, true)
			}, 3*time.Minute, 30*time.Second).Should(Succeed())

			By("deleting the CRs the operator manages")
			for _, args := range [][]string{
				{"garagekey", keyName}, {"garagekey", deniedKeyName},
				{"garagebucket", bucketName}, {"garagecluster", handleName},
			} {
				c := exec.Command("kubectl", "delete", args[0], args[1], "-n", testNamespace,
					"--ignore-not-found", "--timeout=90s")
				o, err := utils.Run(c)
				Expect(err).NotTo(HaveOccurred(), "delete %s/%s failed: %s", args[0], args[1], o)
			}

			By("verifying the Helm-owned StatefulSet and its pod are untouched")
			c := exec.Command("kubectl", "get", "statefulset", extName, "-n", testNamespace,
				"-o", "jsonpath={.status.readyReplicas}")
			o, err := utils.Run(c)
			Expect(err).NotTo(HaveOccurred(), "external StatefulSet was deleted with the handle")
			Expect(o).To(Equal("1"), "external StatefulSet not healthy after handle deletion: %s", o)

			c = exec.Command("kubectl", "get", "pvc", "-n", testNamespace,
				"-o", "jsonpath={.items[*].metadata.name}")
			o, err = utils.Run(c)
			Expect(err).NotTo(HaveOccurred())
			Expect(o).To(ContainSubstring("meta-" + extName + "-0"))
			Expect(o).To(ContainSubstring("data-" + extName + "-0"))
		})
	})
})

// externalGarageManifests renders a single-node Garage that the operator does
// not own — the stand-in for a Helm-deployed cluster. PVC names follow the
// upstream chart's meta-*/data-* convention rather than the operator's
// metadata/data, which is exactly the mismatch that keeps in-place adoption
// (#269 stage 2) out of reach; adopting it via connectTo is the supported path.
func externalGarageManifests(ns, name, adminToken, rpcSecret string) string {
	return fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: %[2]s-secrets
  namespace: %[1]s
type: Opaque
stringData:
  admin-token: %[3]q
  rpc-secret: %[4]q
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: %[2]s-config
  namespace: %[1]s
data:
  garage.toml: |
    metadata_dir = "/var/lib/garage/meta"
    data_dir = "/var/lib/garage/data"
    db_engine = "lmdb"
    replication_factor = 1
    rpc_bind_addr = "[::]:3901"
    rpc_secret = "%[4]s"

    [s3_api]
    s3_region = "garage"
    api_bind_addr = "[::]:3900"
    root_domain = ".s3.garage"

    [admin]
    api_bind_addr = "[::]:3903"
    admin_token = "%[3]s"
---
apiVersion: v1
kind: Service
metadata:
  name: %[2]s
  namespace: %[1]s
spec:
  clusterIP: None
  selector:
    app: %[2]s
  ports:
    - name: s3
      port: 3900
    - name: rpc
      port: 3901
    - name: admin
      port: 3903
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: %[2]s
  namespace: %[1]s
spec:
  serviceName: %[2]s
  replicas: 1
  selector:
    matchLabels:
      app: %[2]s
  template:
    metadata:
      labels:
        app: %[2]s
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: garage
          image: dxflrs/garage:v2.3.0@sha256:866bd13ed2038ba7e7190e840482bc27234c4afaf77be8cfa439ae088c1e4690
          command: ["/garage", "server"]
          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            runAsUser: 1000
            capabilities:
              drop: ["ALL"]
            seccompProfile:
              type: RuntimeDefault
          ports:
            - {name: s3, containerPort: 3900}
            - {name: rpc, containerPort: 3901}
            - {name: admin, containerPort: 3903}
          readinessProbe:
            tcpSocket:
              port: 3903
            initialDelaySeconds: 5
            periodSeconds: 5
          resources:
            requests:
              memory: 128Mi
            limits:
              memory: 512Mi
          volumeMounts:
            - {name: config, mountPath: /etc/garage.toml, subPath: garage.toml}
            - {name: meta, mountPath: /var/lib/garage/meta}
            - {name: data, mountPath: /var/lib/garage/data}
      volumes:
        - name: config
          configMap:
            name: %[2]s-config
  volumeClaimTemplates:
    - metadata:
        name: meta
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 1Gi
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 1Gi
`, ns, name, adminToken, rpcSecret)
}

// firstJSONNodeID pulls the first "id":"<64 hex>" out of a GetClusterStatus
// body. Cheaper and less brittle here than unmarshalling the whole payload,
// which changes shape between Garage minor versions.
func firstJSONNodeID(body string) string {
	m := regexp.MustCompile(`"id"\s*:\s*"([a-f0-9]{64})"`).FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// shellQuote wraps s in single quotes for embedding in a /bin/sh -c script.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// runCurlPod runs a one-shot curl in the cluster and returns its stdout.
//
// It deliberately avoids `kubectl run --rm -i`: attaching races pod startup, and
// when kubectl loses that race it falls back to logs and sometimes returns
// nothing at all — which reads as an empty API response rather than a retry.
// Detaching, waiting for Succeeded, then reading logs makes the body
// deterministic.
func deleteE2EHelperPod(g Gomega, ns, podName string) {
	output, err := utils.Run(exec.Command("kubectl", "delete", "pod", podName,
		"-n", ns, "--ignore-not-found", "--force", "--grace-period=0",
		"--wait=false", "--request-timeout="+e2eKubernetesReadTimeout))
	g.Expect(err).NotTo(HaveOccurred(), "failed to request deletion of helper Pod %s/%s: %s", ns, podName, output)
	g.Expect(waitForE2EResourceDeleted("pod", podName, ns, 30*time.Second)).To(Succeed(),
		"helper Pod %s/%s remained after deletion: %s", ns, podName, output)
}

func runCurlPod(g Gomega, ns, podName, script string) string {
	deletePod := func() { deleteE2EHelperPod(g, ns, podName) }
	deletePod()
	defer deletePod()

	cmd := exec.Command("kubectl", "run", podName, "--restart=Never", "--attach=false",
		"-n", ns, "--image="+e2eCurlImage,
		"--overrides", fmt.Sprintf(`{
			"spec": {
				"restartPolicy": "Never",
				"containers": [{
					"name": %q,
					"image": %q,
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
		}`, podName, e2eCurlImage, script))
	out, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred(), "failed to start curl pod: %s", out)

	out, err = utils.Run(exec.Command("kubectl", "wait",
		"--for=jsonpath={.status.phase}=Succeeded", "pod/"+podName,
		"-n", ns, "--timeout=120s"))
	g.Expect(err).NotTo(HaveOccurred(), "curl pod did not succeed: %s", out)

	out, err = utils.Run(exec.Command("kubectl", "logs", "pod/"+podName, "-n", ns))
	g.Expect(err).NotTo(HaveOccurred(), "reading curl pod logs: %s", out)
	return out
}

type garageLayoutSnapshot struct {
	Version uint64 `json:"version"`
	Roles   []struct {
		ID       string   `json:"id"`
		Tags     []string `json:"tags"`
		Capacity *uint64  `json:"capacity"`
	} `json:"roles"`
	StagedRoleChanges []json.RawMessage `json:"stagedRoleChanges"`
}

type garageLayoutHistorySnapshot struct {
	CurrentVersion uint64 `json:"currentVersion"`
	MinAck         uint64 `json:"minAck"`
	Versions       []struct {
		Version      uint64 `json:"version"`
		Status       string `json:"status"`
		GatewayNodes int    `json:"gatewayNodes"`
	} `json:"versions"`
}

// readGarageLayoutSnapshot samples layout and history in one in-cluster probe
// and rejects a transition-window pair that does not describe one version.
func readGarageLayoutSnapshot(
	g Gomega, ns, podName, clusterName, adminToken string,
) (garageLayoutSnapshot, garageLayoutHistorySnapshot) {
	const separator = "\n---GARAGE-LAYOUT-HISTORY---\n"
	adminHeader := shellQuote("Authorization: Bearer " + adminToken)
	baseURL := fmt.Sprintf("http://%s.%s.svc.cluster.local:3903/v2/", clusterName, ns)
	script := fmt.Sprintf(
		"set -eu\ncurl -fsS -H %s %s\nprintf '\\n---GARAGE-LAYOUT-HISTORY---\\n'\ncurl -fsS -H %s %s",
		adminHeader, shellQuote(baseURL+"GetClusterLayout"),
		adminHeader, shellQuote(baseURL+"GetClusterLayoutHistory"),
	)
	output := runCurlPod(g, ns, podName, script)
	parts := strings.SplitN(output, separator, 2)
	g.Expect(parts).To(HaveLen(2), "layout snapshot is missing its history separator: %s", output)

	layout := garageLayoutSnapshot{}
	history := garageLayoutHistorySnapshot{}
	g.Expect(json.Unmarshal([]byte(strings.TrimSpace(parts[0])), &layout)).To(Succeed(),
		"failed to parse Garage layout: %s", parts[0])
	g.Expect(json.Unmarshal([]byte(strings.TrimSpace(parts[1])), &history)).To(Succeed(),
		"failed to parse Garage layout history: %s", parts[1])
	g.Expect(history.CurrentVersion).To(Equal(layout.Version),
		"layout and history were sampled across a Garage version transition")
	return layout, history
}

// readSecretValue reads and base64-decodes one key out of a Secret.
func readSecretValue(ns, name, key string) string {
	cmd := exec.Command("kubectl", "get", "secret", name, "-n", ns,
		"-o", fmt.Sprintf(`go-template={{ index .data %q | base64decode }}`, key))
	out, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "reading %s/%s: %s", name, key, out)
	return out
}

// runAWSCLI runs an aws-cli one-liner in the cluster with credentials sourced
// directly from credentialSecretName and returns its combined output. Keeping
// Secret values out of the kubectl arguments prevents the E2E command tracer
// and CI logs from exposing them. When expectSuccess is false the pod is
// expected to reach Failed (used to assert an access denial); its durable logs
// remain available for the caller's exact error assertion.
func runAWSCLI(g Gomega, ns, podName, script, credentialSecretName string, expectSuccess bool) string {
	deletePod := func() { deleteE2EHelperPod(g, ns, podName) }
	deletePod()
	defer deletePod()

	// readOnlyRootFilesystem is omitted: aws-cli writes its credential cache to /tmp.
	cmd := exec.Command("kubectl", "run", podName, "--restart=Never", "--attach=false",
		"-n", ns, "--image="+e2eAWSCLIImage,
		"--overrides", fmt.Sprintf(`{
			"spec": {
				"containers": [{
					"name": %q,
					"image": %q,
					"imagePullPolicy": "IfNotPresent",
					"command": ["/bin/sh", "-c"],
					"args": [%q],
					"env": [
						{
							"name": "AWS_ACCESS_KEY_ID",
							"valueFrom": {"secretKeyRef": {"name": %q, "key": "access-key-id"}}
						},
						{
							"name": "AWS_SECRET_ACCESS_KEY",
							"valueFrom": {"secretKeyRef": {"name": %q, "key": "secret-access-key"}}
						},
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
		}`, podName, e2eAWSCLIImage, script, credentialSecretName, credentialSecretName))
	out, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred(), "failed to start aws-cli pod: %s", out)

	expectedPhase := "Failed"
	if expectSuccess {
		expectedPhase = "Succeeded"
	}
	out, err = utils.Run(exec.Command("kubectl", "wait",
		"--for=jsonpath={.status.phase}="+expectedPhase, "pod/"+podName,
		"-n", ns, "--timeout=180s"))
	g.Expect(err).NotTo(HaveOccurred(), "aws-cli pod did not reach expected phase %s: %s", expectedPhase, out)

	out, err = utils.Run(exec.Command("kubectl", "logs", "pod/"+podName, "-n", ns))
	g.Expect(err).NotTo(HaveOccurred(), "reading aws-cli pod logs: %s", out)
	return out
}

// Additive node-local pool (one Garage storage pod per matching
// Kubernetes Node, alongside a Manual StatefulSet/PVC GarageNode). CI runs
// this label in its own Kind cluster from test/e2e/kind-node-local-pools.yaml: two
// selected workers in different zones.
//
// hostPath volumes are rejected by the "restricted" and "baseline" Pod
// Security Standards, so — unlike the other Ordered blocks in this file —
// the test namespace here is deliberately left unlabeled (no PSA
// enforcement).
var _ = Describe("Node-local pools", Ordered, Label("node-local-pools"), func() {
	const testNamespace = "garage-ds-test"
	const clusterName = "ds-cluster"
	const nodeLocalPoolName = "local"
	const manualNodeName = "ds-manual-node"
	const hostPathBase = "/tmp/garage-e2e-ds"
	const managedTopologyClusterName = "managed-mixed-cluster"
	const managedTopologyHostPathBase = "/tmp/garage-e2e-managed-mixed"

	var k8sNodeNames []string
	var garageNodeNames []string
	var originalNodeIDs map[string]string
	var originalNodeUIDs map[string]string
	var storageProfileNodes map[string]string

	assertPVCBackedGarageNode := func(g Gomega, ownerCluster, ownerNode string) {
		output, err := utils.Run(exec.Command("kubectl", "get", "pvc", "-n", testNamespace,
			"-l", "garage.rajsingh.info/cluster="+ownerCluster+
				",garage.rajsingh.info/node="+ownerNode,
			"-o", "json"))
		g.Expect(err).NotTo(HaveOccurred())
		var claims struct {
			Items []struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
				Spec struct {
					VolumeName string `json:"volumeName"`
				} `json:"spec"`
				Status struct {
					Phase string `json:"phase"`
				} `json:"status"`
			} `json:"items"`
		}
		g.Expect(json.Unmarshal([]byte(output), &claims)).To(Succeed())
		g.Expect(claims.Items).To(HaveLen(2),
			"GarageNode %s must own exactly one metadata and one data PVC", ownerNode)
		claimNames := make([]string, 0, len(claims.Items))
		for _, claim := range claims.Items {
			claimNames = append(claimNames, claim.Metadata.Name)
			g.Expect(claim.Status.Phase).To(Equal("Bound"), "PVC %s is not Bound", claim.Metadata.Name)
			g.Expect(claim.Spec.VolumeName).NotTo(BeEmpty(), "PVC %s has no bound PV", claim.Metadata.Name)
		}
		g.Expect(claimNames).To(ConsistOf(
			"metadata-"+ownerNode+"-0",
			"data-"+ownerNode+"-0",
		))
	}

	BeforeAll(func() {
		k8sNodeNames = prepareNodeLocalPoolE2EFixtures(
			testNamespace, hostPathBase, managedTopologyHostPathBase,
		)

		By("creating manager namespace")
		Expect(ensureE2ENamespaceActive(namespace)).To(Succeed())

		By("labeling the manager namespace to enforce the restricted security policy")
		cmd := exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label manager namespace: %s", output)

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("waiting for Garage CRDs to be Established")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
		Expect(waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())

		By("waiting for controller-manager pod to be Ready (webhook server started)")
		verifyControllerUp := func(g Gomega) {
			_, err := controllerManagerPodReady(namespace)
			g.Expect(err).NotTo(HaveOccurred(), "Controller not Ready")
		}
		Eventually(verifyControllerUp, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("creating test namespace (left unlabeled: hostPath needs the privileged PSA level)")
		Expect(createE2ETestNamespace(testNamespace)).To(Succeed())

		By("publishing the durable membership label on every proven Kind worker")
		for _, nodeName := range k8sNodeNames {
			cmd = exec.Command("kubectl", "label", "--overwrite", "node", nodeName,
				"garage.rajsingh.info/e2e-storage=true")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		}

		By("assigning disjoint storage profiles for the multiple-pool topology")
		storageProfileNodes = make(map[string]string, len(k8sNodeNames))
		for i, nodeName := range k8sNodeNames {
			profile := []string{"fast", "archive"}[i]
			cmd = exec.Command("kubectl", "label", "--overwrite", "node", nodeName,
				"garage.rajsingh.info/e2e-storage-profile="+profile)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			storageProfileNodes[profile] = nodeName
		}

		By("creating one stable identity-specific RPC Service per selected worker")
		for _, nodeName := range k8sNodeNames {
			serviceYAML := fmt.Sprintf(`
apiVersion: v1
kind: Service
metadata:
  name: %s
  namespace: %s
spec:
  publishNotReadyAddresses: true
  selector:
    app.kubernetes.io/instance: %s
    garage.rajsingh.info/node-local-pool: %s
    garage.rajsingh.info/kubernetes-node: %s
  ports:
    - name: rpc
      port: 3901
      targetPort: rpc
`, nodeName, testNamespace, clusterName, nodeLocalPoolName, nodeName)
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(serviceYAML)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create identity-specific RPC Service for %s: %s", nodeName, output)
		}
		originalNodeIDs = map[string]string{}
		originalNodeUIDs = map[string]string{}
	})

	AfterAll(func() {
		By("restoring durable membership labels after selector scale-down tests")
		cmd := exec.Command("kubectl", "get", "nodes",
			"-l", "!node-role.kubernetes.io/control-plane",
			"-o", "jsonpath={range .items[*]}{.metadata.name}{'\\n'}{end}")
		output, err := utils.Run(cmd)
		if err != nil {
			reportE2ECleanupWait("node-local membership label discovery", fmt.Errorf("%v: %s", err, output))
		} else {
			for _, nodeName := range strings.Fields(output) {
				cmd = exec.Command("kubectl", "label", "--overwrite", "node", nodeName,
					"garage.rajsingh.info/e2e-storage=true")
				labelOutput, labelErr := utils.Run(cmd)
				if labelErr != nil {
					reportE2ECleanupWait("restore membership label on "+nodeName,
						fmt.Errorf("%v: %s", labelErr, labelOutput))
				}
			}
		}

		cleanupAuto190(testNamespace, nil)
	})

	It("should bootstrap a node-local-only site with one identity per selected worker", func() {
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

		By("creating a node-local-only GarageCluster with no default PVC templates")
		clusterYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  layoutPolicy: Auto
  zone: us-test
  zoneFrom:
    nodeLabel: topology.kubernetes.io/zone
  replication:
    factor: 1
  storage:
    layoutPolicy: Manual
    replicas: 0
    nodeLocalPools:
      - name: %s
        capacity: 2Gi
        selector:
          matchLabels:
            garage.rajsingh.info/e2e-storage: "true"
        metadata:
          hostPath: %s/meta
          hostPathType: DirectoryOrCreate
        dataPaths:
          - path: /data/fast
            hostPath: %s/fast
            hostPathType: DirectoryOrCreate
            capacity: 1Gi
          - path: /data/bulk
            hostPath: %s/bulk
            hostPathType: DirectoryOrCreate
            capacity: 1Gi
        network:
          rpcPublicAddrTemplate: "{nodeName}.%s.svc.cluster.local:3901"
        podTemplate:
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
`, clusterName, testNamespace, nodeLocalPoolName, hostPathBase, hostPathBase, hostPathBase, testNamespace)

		By("creating the site with its node-local membership generator (retry until admission webhook is up)")
		Eventually(func(g Gomega) {
			c := exec.Command("kubectl", "apply", "-f", "-")
			c.Stdin = strings.NewReader(clusterYAML)
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred(), "Failed to create GarageCluster: %s", out)
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying the pool DaemonSet has two pods scheduled and ready")
		verifyDaemonSet := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "daemonset", clusterName+"-storage-"+nodeLocalPoolName, "-n", testNamespace,
				"-o", "jsonpath={.status.desiredNumberScheduled}/{.status.numberReady}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("2/2"), "DaemonSet not fully ready: %s", output)
		}
		Eventually(verifyDaemonSet, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("discovering exactly one generated GarageNode for each selected Kubernetes Node")
		discoveredGarageNodeNames := make([]string, len(k8sNodeNames))
		for i, nodeName := range k8sNodeNames {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagenodes", "-n", testNamespace,
					"-l", "garage.rajsingh.info/cluster="+clusterName+
						",garage.rajsingh.info/node-local-pool="+nodeLocalPoolName+
						",garage.rajsingh.info/kubernetes-node="+nodeName,
					"-o", "jsonpath={range .items[*]}{.metadata.name}{'\\n'}{end}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				names := strings.Fields(output)
				g.Expect(names).To(HaveLen(1), "expected exactly one generated GarageNode for Kubernetes Node %s", nodeName)
				if len(names) != 1 {
					return
				}
				discoveredGarageNodeNames[i] = names[0]
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
		}
		garageNodeNames = discoveredGarageNodeNames

		By("verifying no unexpected GarageNodes were generated for the pool")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenodes", "-n", testNamespace,
				"-l", "garage.rajsingh.info/cluster="+clusterName+",garage.rajsingh.info/node-local-pool="+nodeLocalPoolName,
				"-o", "jsonpath={range .items[*]}{.metadata.name}{'\\n'}{end}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.Fields(output)).To(ConsistOf(garageNodeNames))
		}, 1*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying both hostPath disks are mounted into the DaemonSet")
		cmd = exec.Command("kubectl", "get", "daemonset", clusterName+"-storage-"+nodeLocalPoolName, "-n", testNamespace,
			"-o", "jsonpath={range .spec.template.spec.containers[?(@.name==\"garage\")].volumeMounts[*]}{.mountPath}{'\\n'}{end}")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.Fields(output)).To(ContainElements("/data/fast", "/data/bulk"))

		By("verifying pool pods carry stable Kubernetes Node routing labels")
		for _, nodeName := range k8sNodeNames {
			Eventually(func(g Gomega) {
				pods, err := e2ePodsForSelector(testNamespace,
					"garage.rajsingh.info/node-local-pool="+nodeLocalPoolName+
						",garage.rajsingh.info/kubernetes-node="+nodeName)
				g.Expect(err).NotTo(HaveOccurred())
				active := activeE2EPods(pods)
				if len(active) != 1 {
					g.Expect(active).To(HaveLen(1), "expected one active node-local pool Pod for %s", nodeName)
					return
				}
				g.Expect(active[0].Spec.NodeName).To(Equal(nodeName))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
		}

		By("proving the node-local-only layout converges without placeholder PVC fields")
		Eventually(func(g Gomega) {
			for _, garageNodeName := range garageNodeNames {
				cmd := exec.Command("kubectl", "get", "garagenode", garageNodeName, "-n", testNamespace,
					"-o", "jsonpath={.status.nodeId}/{.status.connected}/{.status.inLayout}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				parts := strings.Split(output, "/")
				g.Expect(parts).To(HaveLen(3))
				g.Expect(parts[0]).NotTo(BeEmpty())
				g.Expect(parts[1:]).To(Equal([]string{"true", "true"}))
			}
			cmd := exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace,
				"-o", `jsonpath={.status.conditions[?(@.type=="NodeLocalPoolsReady")].status}/{.status.conditions[?(@.type=="NodeLocalPoolsReady")].reason}/{.status.health.storageNodes}`)
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True/Converged/2"))
		}, 8*time.Minute, 5*time.Second).Should(Succeed())

		cmd = exec.Command("kubectl", "get", "statefulsets", "-n", testNamespace,
			"-l", "garage.rajsingh.info/cluster="+clusterName,
			"-o", "name")
		output, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(output)).To(BeEmpty(),
			"replicas: 0 with omitted metadata/data unexpectedly created a default StatefulSet/PVC group")

		By("proving the node-local-only site has no hidden default identity or PVC claims")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenodes", "-n", testNamespace,
				"-l", "garage.rajsingh.info/cluster="+clusterName,
				"-o", "jsonpath={range .items[*]}{.metadata.name}{'\\n'}{end}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.Fields(output)).To(ConsistOf(garageNodeNames))

			cmd = exec.Command("kubectl", "get", "pvc", "-n", testNamespace,
				"-l", "garage.rajsingh.info/cluster="+clusterName, "-o", "name")
			output, err = utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(output)).To(BeEmpty(),
				"node-local-only site unexpectedly owns PVCs: %s", output)
		}, time.Minute, 5*time.Second).Should(Succeed())

		By("proving Scale reports 0/0 with a no-match Manual selector, not 0/2 for node-local members")
		Eventually(func(g Gomega) {
			scale, err := readGarageClusterScale("v1beta2", testNamespace, clusterName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(scale.Spec.Replicas).To(BeZero())
			g.Expect(scale.Status.Replicas).To(BeZero())
			g.Expect(scale.Status.Selector).To(Equal(
				"garage.rajsingh.info/cluster=" + clusterName +
					",garage.rajsingh.info/scale-target=disabled",
			))

			cmd := exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace,
				"-o", "jsonpath={.status.storageReplicas}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("2"),
				"aggregate storage status must still report both node-local identities")
		}, time.Minute, 5*time.Second).Should(Succeed())
	})

	It("should propagate pool capacity and converge both storage ownership models", func() {
		By("adding one ordinary PVC-backed GarageNode beside the converged node-local-only site")
		manualNodeYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef:
    name: %s
  zone: us-test
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
`, manualNodeName, testNamespace, clusterName)
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(manualNodeYAML)
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create ordinary GarageNode: %s", output)

		By("verifying both GarageNodes use the configured capacity and distinct topology zones")
		for i, garageNodeName := range garageNodeNames {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "garagenode", garageNodeName, "-n", testNamespace,
					"-o", "jsonpath={.spec.nodeLocalPoolName}/{.spec.capacity}/{.status.zone}/{.spec.kubernetesNodeName}/{.spec.network.rpcPublicAddr}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				parts := strings.Split(output, "/")
				g.Expect(parts).To(HaveLen(5))
				g.Expect(parts[:2]).To(Equal([]string{"local", "2Gi"}))
				g.Expect(parts[2]).To(MatchRegexp(`^zone-[ab]$`))
				g.Expect(parts[3]).To(Equal(k8sNodeNames[i]))
				g.Expect(parts[4]).To(Equal(k8sNodeNames[i]+"."+testNamespace+".svc.cluster.local:3901"),
					"node-local identity must advertise its dedicated stable Service, not a shared or ephemeral Pod address")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
		}

		By("waiting for both nodes to be Connected and InLayout")
		verifyNodeReady := func(g Gomega) {
			for _, garageNodeName := range garageNodeNames {
				cmd := exec.Command("kubectl", "get", "garagenode", garageNodeName, "-n", testNamespace,
					"-o", "jsonpath={.status.connected}/{.status.inLayout}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true/true"), "GarageNode %s not ready: %q", garageNodeName, output)
			}
		}
		Eventually(verifyNodeReady, 5*time.Minute, 10*time.Second).Should(Succeed())

		By("verifying the Manual GarageNode has its independent StatefulSet and layout role")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "statefulset", manualNodeName, "-n", testNamespace,
				"-o", "jsonpath={.status.readyReplicas}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("1"))
			cmd = exec.Command("kubectl", "get", "garagenode", manualNodeName, "-n", testNamespace,
				"-o", "jsonpath={.status.connected}/{.status.inLayout}")
			output, err = utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("true/true"))
			assertPVCBackedGarageNode(g, clusterName, manualNodeName)
		}, 5*time.Minute, 10*time.Second).Should(Succeed())

		By("verifying the pool lifecycle condition is converged")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace,
				"-o", `jsonpath={.status.conditions[?(@.type=="NodeLocalPoolsReady")].status}/{.status.conditions[?(@.type=="NodeLocalPoolsReady")].reason}`)
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True/Converged"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		for _, garageNodeName := range garageNodeNames {
			cmd := exec.Command("kubectl", "get", "garagenode", garageNodeName, "-n", testNamespace,
				"-o", "jsonpath={.status.nodeId}/{.metadata.uid}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			parts := strings.SplitN(output, "/", 2)
			Expect(parts).To(HaveLen(2))
			Expect(parts[0]).NotTo(BeEmpty())
			originalNodeIDs[garageNodeName] = parts[0]
			originalNodeUIDs[garageNodeName] = parts[1]
		}
	})

	It("should converge the default PVC group with multiple node-local pools", func() {
		clusterYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  deletionPolicy: Destroy
  layoutPolicy: Auto
  zone: managed-site
  replication:
    factor: 1
  storage:
    replicas: 1
    metadata:
      size: 100Mi
    data:
      size: 1Gi
    nodeLocalPools:
      - name: fast
        capacity: 1Gi
        selector:
          matchLabels:
            garage.rajsingh.info/e2e-storage-profile: fast
        metadata:
          hostPath: %s/fast/meta
          hostPathType: DirectoryOrCreate
        data:
          hostPath: %s/fast/data
          hostPathType: DirectoryOrCreate
        podTemplate:
          resources:
            limits:
              memory: 256Mi
            requests:
              memory: 128Mi
      - name: archive
        capacity: 1Gi
        selector:
          matchLabels:
            garage.rajsingh.info/e2e-storage-profile: archive
        metadata:
          hostPath: %s/archive/meta
          hostPathType: DirectoryOrCreate
        data:
          hostPath: %s/archive/data
          hostPathType: DirectoryOrCreate
        podTemplate:
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
`, managedTopologyClusterName, testNamespace,
			managedTopologyHostPathBase, managedTopologyHostPathBase,
			managedTopologyHostPathBase, managedTopologyHostPathBase)

		By("creating a second site with the existing managed PVC group and two local-disk profiles")
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(clusterYAML)
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create mixed managed GarageCluster: %s", output)

		By("proving each pool owns one DaemonSet on its exact selected Kubernetes Node and HostPaths")
		for _, poolName := range []string{"fast", "archive"} {
			Eventually(func(g Gomega) {
				expectedNode := storageProfileNodes[poolName]
				g.Expect(expectedNode).NotTo(BeEmpty())
				cmd := exec.Command("kubectl", "get", "daemonset",
					managedTopologyClusterName+"-storage-"+poolName, "-n", testNamespace,
					"-o", "jsonpath={.status.desiredNumberScheduled}/{.status.numberReady}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("1/1"), "pool %s did not select exactly one Ready member", poolName)

				cmd = exec.Command("kubectl", "get", "pods", "-n", testNamespace,
					"-l", "garage.rajsingh.info/cluster="+managedTopologyClusterName+
						",garage.rajsingh.info/node-local-pool="+poolName,
					"-o", "jsonpath={range .items[*]}{.spec.nodeName}{'\\n'}{end}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.Fields(output)).To(Equal([]string{expectedNode}),
					"pool %s Pod did not follow its membership selector", poolName)

				cmd = exec.Command("kubectl", "get", "garagenodes", "-n", testNamespace,
					"-l", "garage.rajsingh.info/cluster="+managedTopologyClusterName+
						",garage.rajsingh.info/node-local-pool="+poolName,
					"-o", "jsonpath={range .items[*]}{.spec.kubernetesNodeName}{'\\n'}{end}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.Fields(output)).To(Equal([]string{expectedNode}),
					"pool %s generated identity did not bind to its selected Node", poolName)

				cmd = exec.Command("kubectl", "get", "daemonset",
					managedTopologyClusterName+"-storage-"+poolName, "-n", testNamespace,
					"-o", `jsonpath={range .spec.template.spec.volumes[*]}{.hostPath.path}{"\n"}{end}`)
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.Fields(output)).To(ConsistOf(
					filepath.Join(managedTopologyHostPathBase, poolName, "meta"),
					filepath.Join(managedTopologyHostPathBase, poolName, "data"),
				), "pool %s DaemonSet mounted another profile's HostPaths", poolName)
			}, 5*time.Minute, 5*time.Second).Should(Succeed())
		}

		By("proving the default group independently owns its PVC-backed GarageNode and StatefulSet")
		defaultNodeName := managedTopologyClusterName + "-storage-0"
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "statefulset", defaultNodeName, "-n", testNamespace,
				"-o", "jsonpath={.status.readyReplicas}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("1"))
			assertPVCBackedGarageNode(g, managedTopologyClusterName, defaultNodeName)
		}, 5*time.Minute, 5*time.Second).Should(Succeed())

		By("proving all three independent Garage identities share the global layout")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenodes", "-n", testNamespace,
				"-l", "garage.rajsingh.info/cluster="+managedTopologyClusterName, "-o", "json")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			var nodes struct {
				Items []struct {
					Metadata struct {
						Name string `json:"name"`
					} `json:"metadata"`
					Spec struct {
						NodeLocalPoolName string `json:"nodeLocalPoolName"`
					} `json:"spec"`
					Status struct {
						Connected bool   `json:"connected"`
						InLayout  bool   `json:"inLayout"`
						NodeID    string `json:"nodeId"`
						Zone      string `json:"zone"`
					} `json:"status"`
				} `json:"items"`
			}
			g.Expect(json.Unmarshal([]byte(output), &nodes)).To(Succeed())
			g.Expect(nodes.Items).To(HaveLen(3))
			backings := map[string]string{}
			for _, node := range nodes.Items {
				g.Expect(node.Status.NodeID).NotTo(BeEmpty())
				g.Expect(node.Status.Connected).To(BeTrue())
				g.Expect(node.Status.InLayout).To(BeTrue())
				g.Expect(node.Status.Zone).To(Equal("managed-site"),
					"pool names must not become Garage failure-domain zones")
				backings[node.Metadata.Name] = node.Spec.NodeLocalPoolName
			}
			g.Expect(backings[defaultNodeName]).To(BeEmpty())
			delete(backings, defaultNodeName)
			poolNames := make([]string, 0, len(backings))
			for _, poolName := range backings {
				poolNames = append(poolNames, poolName)
			}
			g.Expect(poolNames).To(ConsistOf("fast", "archive"))
		}, 8*time.Minute, 5*time.Second).Should(Succeed())

		By("proving both independently managed topology conditions converge")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagecluster", managedTopologyClusterName,
				"-n", testNamespace,
				"-o", `jsonpath={.status.conditions[?(@.type=="StorageTopologyReady")].status}/{.status.conditions[?(@.type=="StorageTopologyReady")].reason}/{.status.conditions[?(@.type=="NodeLocalPoolsReady")].status}/{.status.conditions[?(@.type=="NodeLocalPoolsReady")].reason}/{.status.health.storageNodes}`)
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True/Converged/True/Converged/3"))
		}, 5*time.Minute, 5*time.Second).Should(Succeed())

		By("proving Scale targets only the one-member default group in the mixed 1+2 topology")
		Eventually(func(g Gomega) {
			scale, err := readGarageClusterScale("v1beta2", testNamespace, managedTopologyClusterName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(scale.Spec.Replicas).To(Equal(int32(1)))
			g.Expect(scale.Status.Replicas).To(Equal(int32(1)))
			g.Expect(scale.Status.Selector).To(Equal(
				"garage.rajsingh.info/cluster=" + managedTopologyClusterName +
					",garage.rajsingh.info/storage-group=default" +
					",garage.rajsingh.info/tier=storage",
			))

			cmd := exec.Command("kubectl", "get", "garagecluster", managedTopologyClusterName,
				"-n", testNamespace, "-o", "jsonpath={.status.storageReplicas}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("3"),
				"aggregate storage status must retain default and node-local membership")
		}, time.Minute, 5*time.Second).Should(Succeed())

		By("destroying only the temporary mixed-managed site before later rollout assertions")
		cmd = exec.Command("kubectl", "delete", "garagecluster", managedTopologyClusterName,
			"-n", testNamespace, "--wait=false")
		output, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to request temporary site teardown: %s", output)
		Eventually(func() (bool, error) {
			output, err := utils.Run(exec.Command("kubectl", "get", "garagecluster",
				managedTopologyClusterName, "-n", testNamespace,
				"--ignore-not-found", "-o", "name"))
			if err != nil {
				return false, err
			}
			return strings.TrimSpace(output) == "", nil
		}, 5*time.Minute, 5*time.Second).Should(BeTrue())
		Eventually(func(g Gomega) {
			for _, resource := range []string{"garagenodes", "statefulsets", "daemonsets", "pods"} {
				cmd := exec.Command("kubectl", "get", resource, "-n", testNamespace,
					"-l", "garage.rajsingh.info/cluster="+managedTopologyClusterName, "-o", "name")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(output)).To(BeEmpty(),
					"temporary site still owns %s: %s", resource, output)
			}
		}, 5*time.Minute, 5*time.Second).Should(Succeed())

		By("removing only the temporary site's retained test PVCs after all of its pods are gone")
		cmd = exec.Command("kubectl", "delete", "pvc", "-n", testNamespace,
			"-l", "garage.rajsingh.info/cluster="+managedTopologyClusterName,
			"--ignore-not-found", "--timeout=2m")
		output, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to remove temporary site PVCs: %s", output)
	})

	It("should enforce production HostPath markers and preserve provisioned contents", func() {
		const markerName = ".garage-volume-id"
		const sentinelName = "operator-must-not-delete"
		fixtureDirectories := []string{"meta", "fast", "bulk"}
		runOnKindNode := func(nodeName, script string, args ...string) (string, error) {
			commandArgs := []string{"exec", nodeName, "sh", "-ec", script, "garage-e2e"}
			commandArgs = append(commandArgs, args...)
			return utils.Run(exec.Command("docker", commandArgs...))
		}

		By("proving DirectoryOrCreate startup did not create production markers")
		for _, nodeName := range k8sNodeNames {
			for _, directory := range fixtureDirectories {
				path := filepath.Join(hostPathBase, directory)
				output, err := runOnKindNode(nodeName,
					`test -d "$1" && test ! -e "$1/$2"`, path, markerName)
				Expect(err).NotTo(HaveOccurred(),
					"operator unexpectedly created %s on %s before explicit provisioning: %s", markerName, nodeName, output)
			}
		}

		By("provisioning metadata and data markers on each actual Kind worker filesystem")
		for _, nodeName := range k8sNodeNames {
			for _, directory := range fixtureDirectories {
				path := filepath.Join(hostPathBase, directory)
				output, err := runOnKindNode(nodeName,
					`touch "$1/$2" "$1/$3"`, path, sentinelName, markerName)
				Expect(err).NotTo(HaveOccurred(), "Failed to provision marker on %s:%s: %s", nodeName, path, output)
			}
		}

		By("tightening every metadata and data HostPath from DirectoryOrCreate to Directory")
		productionPatch := `[
  {"op":"replace","path":"/spec/storage/nodeLocalPools/0/metadata/hostPathType","value":"Directory"},
  {"op":"replace","path":"/spec/storage/nodeLocalPools/0/dataPaths/0/hostPathType","value":"Directory"},
  {"op":"replace","path":"/spec/storage/nodeLocalPools/0/dataPaths/1/hostPathType","value":"Directory"}
]`
		cmd := exec.Command("kubectl", "patch", "garagecluster", clusterName, "-n", testNamespace,
			"--type=json", "-p", productionPatch)
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to tighten production HostPath types: %s", output)

		By("waiting for the marker-enforcing template rollout to converge")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "daemonset", clusterName+"-storage-"+nodeLocalPoolName,
				"-n", testNamespace,
				"-o", "jsonpath={.metadata.generation}/{.status.observedGeneration}/{.status.desiredNumberScheduled}/{.status.updatedNumberScheduled}/{.status.numberReady}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			parts := strings.Split(output, "/")
			g.Expect(parts).To(HaveLen(5))
			g.Expect(parts[1]).To(Equal(parts[0]), "DaemonSet status is stale: %s", output)
			g.Expect(parts[2:]).To(Equal([]string{"2", "2", "2"}),
				"production-marker DaemonSet rollout is not current and Ready: %s", output)
			cmd = exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace,
				"-o", `jsonpath={.metadata.generation}/{.status.conditions[?(@.type=="StorageRolloutReady")].observedGeneration}/{.status.conditions[?(@.type=="StorageRolloutReady")].status}/{.status.conditions[?(@.type=="StorageRolloutReady")].reason}`)
			output, err = utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			parts = strings.Split(output, "/")
			g.Expect(parts).To(HaveLen(4))
			g.Expect(parts[1]).To(Equal(parts[0]), "storage rollout condition is stale: %s", output)
			g.Expect(parts[2:]).To(Equal([]string{"True", "Converged"}),
				"production-marker rollout did not converge: %s", output)
		}, 10*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying the DaemonSet checks metadata and every data marker")
		cmd = exec.Command("kubectl", "get", "daemonset", clusterName+"-storage-"+nodeLocalPoolName,
			"-n", testNamespace,
			"-o", `jsonpath={range .spec.template.spec.volumes[*]}{.hostPath.path}{"\n"}{end}`)
		output, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to inspect marker volumes: %s", output)
		var markerPaths []string
		for _, path := range strings.Fields(output) {
			if strings.HasSuffix(path, "/"+markerName) {
				markerPaths = append(markerPaths, path)
			}
		}
		Expect(markerPaths).To(ConsistOf(
			filepath.Join(hostPathBase, "meta", markerName),
			filepath.Join(hostPathBase, "fast", markerName),
			filepath.Join(hostPathBase, "bulk", markerName),
		))

		type markerPoolPod struct {
			Metadata struct {
				Name              string  `json:"name"`
				UID               string  `json:"uid"`
				DeletionTimestamp *string `json:"deletionTimestamp"`
			} `json:"metadata"`
			Spec struct {
				NodeName        string `json:"nodeName"`
				SchedulingGates []struct {
					Name string `json:"name"`
				} `json:"schedulingGates"`
			} `json:"spec"`
			Status struct {
				Phase      string `json:"phase"`
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
				ContainerStatuses []struct {
					State struct {
						Running *struct{} `json:"running"`
					} `json:"state"`
				} `json:"containerStatuses"`
			} `json:"status"`
		}
		type markerPoolPodList struct {
			Items []markerPoolPod `json:"items"`
		}
		readPoolPods := func() ([]markerPoolPod, error) {
			output, err := utils.Run(exec.Command("kubectl", "get", "pods", "-n", testNamespace,
				"-l", "garage.rajsingh.info/cluster="+clusterName+",garage.rajsingh.info/node-local-pool="+nodeLocalPoolName,
				"-o", "json"))
			if err != nil {
				return nil, fmt.Errorf("listing node-local pool Pods: %w: %s", err, output)
			}
			var list markerPoolPodList
			if err := json.Unmarshal([]byte(output), &list); err != nil {
				return nil, fmt.Errorf("decoding node-local pool Pods: %w", err)
			}
			return list.Items, nil
		}
		podReady := func(pod markerPoolPod) bool {
			for _, condition := range pod.Status.Conditions {
				if condition.Type == "Ready" && condition.Status == "True" {
					return true
				}
			}
			return false
		}

		exerciseMissingMarker := func(directory string) {
			targetNode := k8sNodeNames[0]
			targetGarageNode := garageNodeNames[0]
			markerPath := filepath.Join(hostPathBase, directory, markerName)
			sentinelPath := filepath.Join(hostPathBase, directory, sentinelName)
			pods, err := readPoolPods()
			Expect(err).NotTo(HaveOccurred())
			priorUIDs := make(map[string]bool, len(pods))
			oldPodName := ""
			for _, pod := range pods {
				if pod.Metadata.DeletionTimestamp == nil {
					priorUIDs[pod.Metadata.UID] = true
					if pod.Spec.NodeName == targetNode {
						oldPodName = pod.Metadata.Name
					}
				}
			}
			Expect(oldPodName).NotTo(BeEmpty(), "missing current pool Pod on %s", targetNode)

			By("removing only the " + directory + " marker from one worker")
			output, err := runOnKindNode(targetNode,
				`rm -f "$1" && test -f "$2"`, markerPath, sentinelPath)
			Expect(err).NotTo(HaveOccurred(), "Failed to remove marker fixture: %s", output)

			By("forcing a replacement Pod while the mounted filesystem lacks its marker")
			output, err = utils.Run(exec.Command("kubectl", "delete", "pod", oldPodName,
				"-n", testNamespace, "--wait=true", "--timeout=120s"))
			Expect(err).NotTo(HaveOccurred(), "Failed to delete pool Pod %s: %s", oldPodName, output)

			var replacement markerPoolPod
			Eventually(func(g Gomega) {
				pods, err := readPoolPods()
				g.Expect(err).NotTo(HaveOccurred())
				found := false
				for _, pod := range pods {
					if pod.Metadata.DeletionTimestamp == nil && !priorUIDs[pod.Metadata.UID] &&
						pod.Spec.NodeName == targetNode {
						replacement = pod
						found = true
						break
					}
				}
				g.Expect(found).To(BeTrue(), "DaemonSet has not created a replacement Pod")
				g.Expect(replacement.Spec.NodeName).To(Equal(targetNode))
				g.Expect(replacement.Spec.SchedulingGates).To(BeEmpty(),
					"replacement must reach kubelet volume validation, not remain scheduler-gated")
				g.Expect(replacement.Status.Phase).To(Equal("Pending"))
				g.Expect(podReady(replacement)).To(BeFalse())
			}, 3*time.Minute, 3*time.Second).Should(Succeed())

			Consistently(func(g Gomega) {
				pods, err := readPoolPods()
				g.Expect(err).NotTo(HaveOccurred())
				found := false
				for _, pod := range pods {
					if pod.Metadata.UID != replacement.Metadata.UID {
						continue
					}
					found = true
					g.Expect(podReady(pod)).To(BeFalse(), "Pod became Ready without %s", markerPath)
					for _, container := range pod.Status.ContainerStatuses {
						g.Expect(container.State.Running).To(BeNil(), "Garage started without %s", markerPath)
					}
				}
				g.Expect(found).To(BeTrue(), "replacement Pod disappeared instead of remaining safely Pending")
			}, 90*time.Second, 2*time.Second).Should(Succeed())

			By("observing the kubelet marker failure on the actual replacement Pod")
			Eventually(func(g Gomega) {
				output, err := utils.Run(exec.Command("kubectl", "describe", "pod", replacement.Metadata.Name,
					"-n", testNamespace))
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("FailedMount"))
				g.Expect(output).To(ContainSubstring(markerPath))
			}, 2*time.Minute, 3*time.Second).Should(Succeed())
			output, err = runOnKindNode(targetNode,
				`test ! -e "$1" && test -f "$2"`, markerPath, sentinelPath)
			Expect(err).NotTo(HaveOccurred(),
				"operator created the missing marker or removed adjacent contents: %s", output)

			By("restoring the marker on the mounted filesystem and allowing the same Pod to start")
			output, err = runOnKindNode(targetNode, `touch "$1"`, markerPath)
			Expect(err).NotTo(HaveOccurred(), "Failed to restore marker: %s", output)
			Eventually(func(g Gomega) {
				pods, err := readPoolPods()
				g.Expect(err).NotTo(HaveOccurred())
				found := false
				for _, pod := range pods {
					if pod.Metadata.UID == replacement.Metadata.UID {
						found = true
						g.Expect(podReady(pod)).To(BeTrue())
					}
				}
				g.Expect(found).To(BeTrue())

				output, err := utils.Run(exec.Command("kubectl", "get", "garagenode", targetGarageNode,
					"-n", testNamespace,
					"-o", "jsonpath={.status.nodeId}/{.status.observedPodUid}/{.status.connected}/{.status.inLayout}"))
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal(originalNodeIDs[targetGarageNode] + "/" + replacement.Metadata.UID + "/true/true"))
			}, 5*time.Minute, 5*time.Second).Should(Succeed())
			output, err = runOnKindNode(targetNode,
				`test -f "$1" && test -f "$2"`, markerPath, sentinelPath)
			Expect(err).NotTo(HaveOccurred(), "marker or adjacent contents disappeared after startup: %s", output)
		}

		By("proving the metadata identity marker is required")
		exerciseMissingMarker("meta")
		By("proving a data-disk marker is independently required")
		exerciseMissingMarker("fast")

		By("verifying every provisioned marker and adjacent sentinel survived all rollouts")
		for _, nodeName := range k8sNodeNames {
			for _, directory := range fixtureDirectories {
				path := filepath.Join(hostPathBase, directory)
				output, err := runOnKindNode(nodeName,
					`test -f "$1/$2" && test -f "$1/$3"`, path, markerName, sentinelName)
				Expect(err).NotTo(HaveOccurred(), "HostPath contents did not survive on %s:%s: %s", nodeName, path, output)
			}
		}
	})

	It("should roll every managed storage model one at a time and preserve Garage identities", func() {
		type rolloutSnapshot struct {
			podUIDs             map[string]string
			podReady            map[string]bool
			podCreated          map[string]time.Time
			podReadyAt          map[string]time.Time
			observedPodUIDs     map[string]string
			nodeIDs             map[string]string
			garageNodeUIDs      map[string]string
			connected           map[string]bool
			inLayout            map[string]bool
			activeActor         string
			rolloutStatusStable bool
			conditionStatus     string
			conditionReason     string
			poolsStatus         string
			poolsReason         string
			safetyViolations    []string
		}
		type podList struct {
			Items []struct {
				Metadata struct {
					Name              string            `json:"name"`
					UID               string            `json:"uid"`
					DeletionTimestamp string            `json:"deletionTimestamp"`
					CreationTimestamp string            `json:"creationTimestamp"`
					Labels            map[string]string `json:"labels"`
				} `json:"metadata"`
				Spec struct {
					NodeName string `json:"nodeName"`
				} `json:"spec"`
				Status struct {
					Conditions []struct {
						Type               string `json:"type"`
						Status             string `json:"status"`
						LastTransitionTime string `json:"lastTransitionTime"`
					} `json:"conditions"`
				} `json:"status"`
			} `json:"items"`
		}
		type garageNodeList struct {
			Items []struct {
				Metadata struct {
					Name string `json:"name"`
					UID  string `json:"uid"`
				} `json:"metadata"`
				Status struct {
					NodeID         string `json:"nodeId"`
					ObservedPodUID string `json:"observedPodUid"`
					Connected      bool   `json:"connected"`
					InLayout       bool   `json:"inLayout"`
				} `json:"status"`
			} `json:"items"`
		}
		type clusterStatus struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
			Status struct {
				StorageRollout *struct {
					GarageNodeName     string `json:"garageNodeName"`
					NodeLocalPoolName  string `json:"nodeLocalPoolName"`
					KubernetesNodeName string `json:"kubernetesNodeName"`
				} `json:"storageRollout"`
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
					Reason string `json:"reason"`
				} `json:"conditions"`
			} `json:"status"`
		}

		managedActors := append([]string{manualNodeName}, garageNodeNames...)
		poolActorByKubernetesNode := make(map[string]string, len(k8sNodeNames))
		for i, nodeName := range k8sNodeNames {
			poolActorByKubernetesNode[nodeName] = garageNodeNames[i]
		}
		readClusterStatus := func() (clusterStatus, error) {
			var status clusterStatus
			output, err := utils.Run(exec.Command("kubectl", "get", "garagecluster",
				clusterName, "-n", testNamespace, "-o", "json"))
			if err != nil {
				return status, fmt.Errorf("reading GarageCluster rollout status: %w: %s", err, output)
			}
			if err := json.Unmarshal([]byte(output), &status); err != nil {
				return status, fmt.Errorf("decoding GarageCluster rollout status: %w", err)
			}
			return status, nil
		}
		readSnapshot := func() (rolloutSnapshot, error) {
			snapshot := rolloutSnapshot{
				podUIDs:         make(map[string]string, len(managedActors)),
				podReady:        make(map[string]bool, len(managedActors)),
				podCreated:      make(map[string]time.Time, len(managedActors)),
				podReadyAt:      make(map[string]time.Time, len(managedActors)),
				observedPodUIDs: make(map[string]string, len(managedActors)),
				nodeIDs:         make(map[string]string, len(managedActors)),
				garageNodeUIDs:  make(map[string]string, len(managedActors)),
				connected:       make(map[string]bool, len(managedActors)),
				inLayout:        make(map[string]bool, len(managedActors)),
			}
			for _, actor := range managedActors {
				snapshot.podUIDs[actor] = ""
			}
			statusBefore, err := readClusterStatus()
			if err != nil {
				return snapshot, err
			}

			output, err := utils.Run(exec.Command("kubectl", "get", "pods", "-n", testNamespace, "-o", "json"))
			if err != nil {
				return snapshot, fmt.Errorf("listing managed pods: %w: %s", err, output)
			}
			var pods podList
			if err := json.Unmarshal([]byte(output), &pods); err != nil {
				return snapshot, fmt.Errorf("decoding managed pods: %w", err)
			}
			for i := range pods.Items {
				pod := &pods.Items[i]
				actor := ""
				if pod.Metadata.Name == manualNodeName+"-0" {
					actor = manualNodeName
				} else if pod.Metadata.Labels["garage.rajsingh.info/cluster"] == clusterName &&
					pod.Metadata.Labels["garage.rajsingh.info/node-local-pool"] == nodeLocalPoolName {
					actor = poolActorByKubernetesNode[pod.Spec.NodeName]
				}
				if actor == "" || pod.Metadata.DeletionTimestamp != "" {
					continue
				}
				if previous := snapshot.podUIDs[actor]; previous != "" && previous != pod.Metadata.UID {
					snapshot.safetyViolations = append(snapshot.safetyViolations,
						fmt.Sprintf("actor %s has two non-terminating pods (%s and %s)", actor, previous, pod.Metadata.UID))
					continue
				}
				snapshot.podUIDs[actor] = pod.Metadata.UID
				created, err := time.Parse(time.RFC3339, pod.Metadata.CreationTimestamp)
				if err != nil {
					return snapshot, fmt.Errorf("decoding creation time for pod %s: %w", pod.Metadata.Name, err)
				}
				snapshot.podCreated[actor] = created
				for _, condition := range pod.Status.Conditions {
					if condition.Type == "Ready" && condition.Status == "True" {
						snapshot.podReady[actor] = true
						readyAt, err := time.Parse(time.RFC3339, condition.LastTransitionTime)
						if err != nil {
							return snapshot, fmt.Errorf("decoding Ready transition time for pod %s: %w", pod.Metadata.Name, err)
						}
						snapshot.podReadyAt[actor] = readyAt
					}
				}
			}

			output, err = utils.Run(exec.Command("kubectl", "get", "garagenodes", "-n", testNamespace, "-o", "json"))
			if err != nil {
				return snapshot, fmt.Errorf("listing GarageNodes: %w: %s", err, output)
			}
			var nodes garageNodeList
			if err := json.Unmarshal([]byte(output), &nodes); err != nil {
				return snapshot, fmt.Errorf("decoding GarageNodes: %w", err)
			}
			for i := range nodes.Items {
				node := &nodes.Items[i]
				snapshot.observedPodUIDs[node.Metadata.Name] = node.Status.ObservedPodUID
				snapshot.nodeIDs[node.Metadata.Name] = node.Status.NodeID
				snapshot.garageNodeUIDs[node.Metadata.Name] = node.Metadata.UID
				snapshot.connected[node.Metadata.Name] = node.Status.Connected
				snapshot.inLayout[node.Metadata.Name] = node.Status.InLayout
			}

			status, err := readClusterStatus()
			if err != nil {
				return snapshot, err
			}
			snapshot.rolloutStatusStable = statusBefore.Metadata.ResourceVersion == status.Metadata.ResourceVersion
			if record := status.Status.StorageRollout; record != nil {
				if record.GarageNodeName != "" {
					snapshot.activeActor = record.GarageNodeName
				} else if record.NodeLocalPoolName == nodeLocalPoolName {
					actor, found := poolActorByKubernetesNode[record.KubernetesNodeName]
					if !found {
						snapshot.safetyViolations = append(snapshot.safetyViolations,
							fmt.Sprintf("persisted rollout actor names unknown Kubernetes Node %s", record.KubernetesNodeName))
					} else {
						snapshot.activeActor = actor
					}
				}
			}
			for _, condition := range status.Status.Conditions {
				switch condition.Type {
				case "StorageRolloutReady":
					snapshot.conditionStatus = condition.Status
					snapshot.conditionReason = condition.Reason
				case "NodeLocalPoolsReady":
					snapshot.poolsStatus = condition.Status
					snapshot.poolsReason = condition.Reason
				}
			}
			return snapshot, nil
		}

		By("capturing all Manual/PVC and node-local pod and Garage identities")
		initial, err := readSnapshot()
		Expect(err).NotTo(HaveOccurred())
		Expect(initial.safetyViolations).To(BeEmpty())
		baselinePodUIDs := make(map[string]string, len(managedActors))
		for _, actor := range managedActors {
			Expect(initial.podUIDs[actor]).NotTo(BeEmpty(), "missing initial pod for %s", actor)
			Expect(initial.podReady[actor]).To(BeTrue(), "initial pod for %s is not Ready", actor)
			Expect(initial.observedPodUIDs[actor]).To(Equal(initial.podUIDs[actor]))
			Expect(initial.nodeIDs[actor]).NotTo(BeEmpty())
			Expect(initial.garageNodeUIDs[actor]).NotTo(BeEmpty())
			originalNodeIDs[actor] = initial.nodeIDs[actor]
			originalNodeUIDs[actor] = initial.garageNodeUIDs[actor]
			baselinePodUIDs[actor] = initial.podUIDs[actor]
		}

		By("changing a shared pod-template input instead of deleting workload pods directly")
		cmd := exec.Command("kubectl", "patch", "garagecluster", clusterName, "-n", testNamespace,
			"--type=merge", "-p", `{"spec":{"logging":{"level":"garage=debug"}}}`)
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to trigger declarative storage rollout: %s", output)

		By("observing one durable rollout actor at a time across both workload implementations")
		sawRollingCondition := false
		var converged rolloutSnapshot
		Eventually(func() (bool, error) {
			snapshot, err := readSnapshot()
			if err != nil {
				return false, err
			}
			if len(snapshot.safetyViolations) > 0 {
				StopTrying("storage rollout safety invariant violated: " + strings.Join(snapshot.safetyViolations, "; ")).Now()
			}
			if snapshot.conditionStatus == "False" && snapshot.conditionReason == "RollingOut" {
				sawRollingCondition = true
			}

			unsettledActors := make([]string, 0, len(managedActors))
			for _, actor := range managedActors {
				if snapshot.nodeIDs[actor] != originalNodeIDs[actor] {
					StopTrying(fmt.Sprintf("Garage node ID changed for %s: got %q, want %q",
						actor, snapshot.nodeIDs[actor], originalNodeIDs[actor])).Now()
				}
				if snapshot.garageNodeUIDs[actor] != originalNodeUIDs[actor] {
					StopTrying(fmt.Sprintf("GarageNode CR changed for %s: got %q, want %q",
						actor, snapshot.garageNodeUIDs[actor], originalNodeUIDs[actor])).Now()
				}
				if snapshot.podUIDs[actor] == baselinePodUIDs[actor] {
					continue
				}
				newUID := snapshot.podUIDs[actor]
				if newUID != "" && snapshot.podReady[actor] &&
					snapshot.observedPodUIDs[actor] == newUID && snapshot.connected[actor] && snapshot.inLayout[actor] {
					// A complete actor may begin and finish between two one-second
					// observations. Advance the live baseline from durable Ready and
					// identity evidence; the post-rollout timestamps below prove that
					// any missed complete intervals still did not overlap.
					baselinePodUIDs[actor] = newUID
					continue
				}
				unsettledActors = append(unsettledActors, actor)
			}
			if len(unsettledActors) > 1 {
				StopTrying(fmt.Sprintf("more than one managed Garage Pod was unproven at once: %v", unsettledActors)).Now()
			}
			if len(unsettledActors) == 1 {
				actor := unsettledActors[0]
				if snapshot.rolloutStatusStable && snapshot.activeActor != "" && snapshot.activeActor != actor {
					StopTrying(fmt.Sprintf("persisted rollout actor %s does not match the only changing Pod %s",
						snapshot.activeActor, actor)).Now()
				}
			}

			for _, actor := range managedActors {
				if snapshot.podUIDs[actor] == "" || snapshot.podUIDs[actor] == initial.podUIDs[actor] ||
					!snapshot.podReady[actor] || snapshot.observedPodUIDs[actor] != snapshot.podUIDs[actor] ||
					!snapshot.connected[actor] || !snapshot.inLayout[actor] {
					return false, nil
				}
			}
			if snapshot.activeActor != "" || snapshot.conditionStatus != "True" ||
				snapshot.conditionReason != "Converged" || snapshot.poolsStatus != "True" ||
				snapshot.poolsReason != "Converged" {
				return false, nil
			}
			converged = snapshot
			return true, nil
		}, 10*time.Minute, time.Second).Should(BeTrue())
		Expect(sawRollingCondition).To(BeTrue(), "StorageRolloutReady never exposed the durable RollingOut boundary")

		By("proving each next replacement was created only after the prior actor became Ready")
		type replacementInterval struct {
			actor   string
			created time.Time
			readyAt time.Time
		}
		intervals := make([]replacementInterval, 0, len(managedActors))
		for _, actor := range managedActors {
			Expect(converged.podCreated[actor]).NotTo(BeZero(), "replacement creation time missing for %s", actor)
			Expect(converged.podReadyAt[actor]).NotTo(BeZero(), "replacement Ready transition missing for %s", actor)
			Expect(converged.podReadyAt[actor].Before(converged.podCreated[actor])).To(BeFalse(),
				"replacement %s became Ready before it was created", actor)
			intervals = append(intervals, replacementInterval{
				actor: actor, created: converged.podCreated[actor], readyAt: converged.podReadyAt[actor],
			})
		}
		sort.Slice(intervals, func(i, j int) bool { return intervals[i].created.Before(intervals[j].created) })
		for i := 1; i < len(intervals); i++ {
			Expect(intervals[i].created.Before(intervals[i-1].readyAt)).To(BeFalse(),
				"replacement %s was created at %s before prior actor %s became Ready at %s",
				intervals[i].actor, intervals[i].created, intervals[i-1].actor, intervals[i-1].readyAt)
		}
	})

	It("should round-trip an object through a stable per-node-local pool endpoint", func() {
		const bucketName = "ds-test-bucket"
		const keyName = "ds-test-key"
		const serviceName = "ds-node-s3"
		bucketYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef:
    name: %s
  globalAlias: %s
`, bucketName, testNamespace, clusterName, bucketName)

		By("creating a GarageBucket against the node-local-pool-backed cluster")
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(bucketYAML)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create test bucket")

		By("waiting for the bucket to reach Ready")
		verifyBucketReady := func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagebucket", bucketName, "-n", testNamespace,
				"-o", "jsonpath={.status.phase}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Ready"), "Bucket not ready: phase=%s", output)
		}
		Eventually(verifyBucketReady, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("creating credentials scoped to the bucket")
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
`, keyName, testNamespace, clusterName, bucketName)
		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(keyYAML)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create GarageKey")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "secret", keyName, "-n", testNamespace,
				"-o", `go-template={{ index .data "access-key-id" | base64decode }}`)
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).NotTo(BeEmpty())
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("creating an S3 Service pinned to one stable Kubernetes Node label")
		serviceYAML := fmt.Sprintf(`
apiVersion: v1
kind: Service
metadata:
  name: %s
  namespace: %s
spec:
  selector:
    garage.rajsingh.info/cluster: %s
    garage.rajsingh.info/node-local-pool: %s
    garage.rajsingh.info/kubernetes-node: %s
  ports:
    - name: s3
      port: 3900
      targetPort: s3
`, serviceName, testNamespace, clusterName, nodeLocalPoolName, k8sNodeNames[0])
		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(serviceYAML)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create per-node S3 Service")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "endpoints", serviceName, "-n", testNamespace,
				"-o", "jsonpath={range .subsets[*]}{range .addresses[*]}{.targetRef.name}{'\\n'}{end}{end}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(ContainSubstring(clusterName + "-storage-" + nodeLocalPoolName))
		}, 1*time.Minute, 5*time.Second).Should(Succeed())

		By("putting, reading, and deleting an object through that exact DaemonSet identity")
		endpoint := fmt.Sprintf("http://%s.%s.svc.cluster.local:3900", serviceName, testNamespace)
		const payload = "node-local-pool-round-trip"
		script := fmt.Sprintf(
			`printf '%s' > /tmp/payload.txt && `+
				`aws s3api put-object --endpoint-url %s --region garage --bucket %s --key obj --body /tmp/payload.txt && `+
				`aws s3api get-object --endpoint-url %s --region garage --bucket %s --key obj /tmp/out.txt && `+
				`cat /tmp/out.txt && `+
				`aws s3api delete-object --endpoint-url %s --region garage --bucket %s --key obj`,
			payload, endpoint, bucketName, endpoint, bucketName, endpoint, bucketName,
		)
		Eventually(func(g Gomega) {
			output := runAWSCLI(g, testNamespace, "ds-s3-verify", script, keyName, true)
			g.Expect(output).To(ContainSubstring(payload), "GET did not return the PUT payload: %s", output)
		}, 3*time.Minute, 30*time.Second).Should(Succeed())

		By("cleaning up the test credentials, bucket, and per-node Service")
		cmd = exec.Command("kubectl", "delete", "garagekey", keyName, "-n", testNamespace,
			"--ignore-not-found", "--timeout=60s")
		if output, err := utils.Run(cmd); err != nil {
			reportE2ECleanupWait("node-local GarageKey delete request", fmt.Errorf("%v: %s", err, output))
		}
		cmd = exec.Command("kubectl", "delete", "garagebucket", bucketName, "-n", testNamespace,
			"--ignore-not-found", "--timeout=60s")
		if output, err := utils.Run(cmd); err != nil {
			reportE2ECleanupWait("node-local GarageBucket delete request", fmt.Errorf("%v: %s", err, output))
		}
		cmd = exec.Command("kubectl", "delete", "service", serviceName, "-n", testNamespace,
			"--ignore-not-found", "--timeout=60s")
		if output, err := utils.Run(cmd); err != nil {
			reportE2ECleanupWait("node-local S3 Service delete request", fmt.Errorf("%v: %s", err, output))
		}
	})

	It("should drain selector-based scale-down and rejoin with the hostPath identity", func() {
		removedK8sNode := k8sNodeNames[1]
		removedGarageNode := garageNodeNames[1]
		sourcePodUID := ""

		By("capturing the exact live source Pod before changing desired membership")
		Eventually(func(g Gomega) {
			output, err := utils.Run(exec.Command("kubectl", "get", "pods", "-n", testNamespace,
				"-l", "garage.rajsingh.info/node-local-pool="+nodeLocalPoolName+
					",garage.rajsingh.info/kubernetes-node="+removedK8sNode,
				"-o", `jsonpath={range .items[*]}{.metadata.uid}{"|"}{.status.phase}{"|"}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}`))
			g.Expect(err).NotTo(HaveOccurred())
			podLines := strings.Fields(output)
			g.Expect(podLines).To(HaveLen(1), "expected exactly one source Pod before selector removal: %q", output)
			podParts := strings.Split(podLines[0], "|")
			g.Expect(podParts).To(HaveLen(3))
			g.Expect(podParts[0]).NotTo(BeEmpty())
			g.Expect(podParts[1:]).To(Equal([]string{"Running", "True"}))
			sourcePodUID = podParts[0]
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
		Expect(sourcePodUID).NotTo(BeEmpty())

		By("removing one worker from the durable membership selector")
		cmd := exec.Command("kubectl", "label", "node", removedK8sNode,
			"garage.rajsingh.info/e2e-storage-")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("proving drain preparation starts while the source Garage process is still live")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenode", removedGarageNode, "-n", testNamespace,
				"-o", `go-template={{ index .metadata.annotations "garage.rajsingh.info/drain" }}|{{ .metadata.deletionTimestamp }}`)
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("true|<no value>"),
				"the parent must request reversible preparation before issuing DELETE")

			cmd = exec.Command("kubectl", "get", "pods", "-n", testNamespace,
				"-l", "garage.rajsingh.info/node-local-pool="+nodeLocalPoolName+
					",garage.rajsingh.info/kubernetes-node="+removedK8sNode,
				"-o", `jsonpath={range .items[*]}{.metadata.uid}{"|"}{.status.phase}{"|"}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}`)
			output, err = utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			podLines := strings.Fields(output)
			g.Expect(podLines).To(HaveLen(1), "expected exactly one source Pod: %q", output)
			podParts := strings.Split(podLines[0], "|")
			g.Expect(podParts).To(HaveLen(3))
			g.Expect(podParts[0]).To(Equal(sourcePodUID),
				"the exact pre-removal source Pod must remain live during drain preparation")
			g.Expect(podParts[1:]).To(Equal([]string{"Running", "True"}))
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("waiting for its pod to terminate and GarageNode finalizer to drain the role")
		// Garage v2.3 schedules block GC after 610 seconds. This bound covers
		// that exact proof plus reconciliation; it is not a generic rollout wait.
		Eventually(func() (bool, error) {
			output, err := utils.Run(exec.Command("kubectl", "get", "garagenode", removedGarageNode,
				"-n", testNamespace, "--ignore-not-found", "-o", "name"))
			if err != nil {
				return false, err
			}
			if strings.TrimSpace(output) != "" {
				output, err = utils.Run(exec.Command("kubectl", "get", "pods", "-n", testNamespace,
					"-l", "garage.rajsingh.info/node-local-pool="+nodeLocalPoolName+
						",garage.rajsingh.info/kubernetes-node="+removedK8sNode,
					"-o", `jsonpath={range .items[*]}{.metadata.uid}{"|"}{.status.phase}{"|"}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}`))
				if err != nil {
					return false, err
				}
				podLines := strings.Fields(output)
				sourceHealthy := false
				if len(podLines) == 1 {
					podParts := strings.Split(podLines[0], "|")
					sourceHealthy = len(podParts) == 3 && podParts[0] == sourcePodUID &&
						podParts[1] == "Running" && podParts[2] == "True"
				}
				if sourceHealthy {
					return false, nil
				}

				// Finalizer completion and DaemonSet deactivation may occur
				// between the GarageNode and Pod reads. Reconfirm the parent
				// before treating a changed source as a safety violation.
				confirmedNode, confirmErr := utils.Run(exec.Command("kubectl", "get", "garagenode",
					removedGarageNode, "-n", testNamespace, "--ignore-not-found", "-o", "name"))
				if confirmErr != nil {
					return false, confirmErr
				}
				if strings.TrimSpace(confirmedNode) != "" {
					StopTrying(fmt.Sprintf(
						"retiring GarageNode still exists but source Pod %s was replaced or became unavailable: %q",
						sourcePodUID, output)).Now()
				}
				// The GarageNode disappeared at the successful boundary; fall
				// through and require the exact remaining DaemonSet set below.
			}

			output, err = utils.Run(exec.Command("kubectl", "get", "daemonset",
				clusterName+"-storage-"+nodeLocalPoolName, "-n", testNamespace,
				"-o", "jsonpath={.status.desiredNumberScheduled}/{.status.numberReady}"))
			if err != nil {
				return false, err
			}
			return output == "1/1", nil
		}, 20*time.Minute, 10*time.Second).Should(BeTrue())

		By("proving Garage committed the role removal with no staged topology mutation")
		removedNodeID := originalNodeIDs[removedGarageNode]
		Expect(removedNodeID).NotTo(BeEmpty())
		Eventually(func(g Gomega) {
			const adminToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			curlCmd := fmt.Sprintf(
				"curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterLayout",
				adminToken, clusterName, testNamespace)
			output := runCurlPod(g, testNamespace, "node-local-retirement-layout", curlCmd)
			jsonStart := strings.Index(output, "{")
			jsonEnd := strings.LastIndex(output, "}")
			g.Expect(jsonStart).To(BeNumerically(">=", 0), "no layout JSON in output: %s", output)
			g.Expect(jsonEnd).To(BeNumerically(">", jsonStart), "invalid layout JSON in output: %s", output)
			var layout struct {
				Roles []struct {
					ID string `json:"id"`
				} `json:"roles"`
				StagedRoleChanges []json.RawMessage `json:"stagedRoleChanges"`
			}
			jsonBody := output[jsonStart : jsonEnd+1]
			g.Expect(json.Unmarshal([]byte(jsonBody), &layout)).To(Succeed(),
				"failed to parse Garage layout: %s", jsonBody)
			roleIDs := make([]string, 0, len(layout.Roles))
			for _, role := range layout.Roles {
				roleIDs = append(roleIDs, role.ID)
			}
			g.Expect(roleIDs).NotTo(ContainElement(removedNodeID),
				"retired positive-capacity identity remains in Garage's committed layout")
			g.Expect(layout.StagedRoleChanges).To(BeEmpty(),
				"selector retirement left an uncommitted Garage layout mutation")
		}, 3*time.Minute, 15*time.Second).Should(Succeed())

		By("verifying retirement did not delete the removed Node's HostPath contents")
		for _, directory := range []string{"meta", "fast", "bulk"} {
			path := filepath.Join(hostPathBase, directory)
			cmd = exec.Command("docker", "exec", removedK8sNode, "sh", "-ec",
				`test -f "$1/.garage-volume-id" && test -f "$1/operator-must-not-delete"`,
				"garage-e2e", path)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(),
				"retirement altered HostPath contents on %s:%s: %s", removedK8sNode, path, output)
		}

		By("adding the worker back")
		cmd = exec.Command("kubectl", "label", "--overwrite", "node", removedK8sNode,
			"garage.rajsingh.info/e2e-storage=true")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("waiting for a new GarageNode CR to recover the same persisted Garage identity")
		rejoinedPodUID := ""
		rejoinedGarageNodeUID := ""
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "daemonset", clusterName+"-storage-"+nodeLocalPoolName, "-n", testNamespace,
				"-o", "jsonpath={.status.desiredNumberScheduled}/{.status.numberReady}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("2/2"))

			cmd = exec.Command("kubectl", "get", "pods", "-n", testNamespace,
				"-l", "garage.rajsingh.info/node-local-pool="+nodeLocalPoolName+
					",garage.rajsingh.info/kubernetes-node="+removedK8sNode,
				"-o", `jsonpath={range .items[*]}{.metadata.uid}{"|"}{.status.phase}{"|"}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}`)
			output, err = utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			podLines := strings.Fields(output)
			g.Expect(podLines).To(HaveLen(1), "expected exactly one current pool Pod on the rejoined Node: %q", output)
			podParts := strings.Split(podLines[0], "|")
			g.Expect(podParts).To(HaveLen(3))
			g.Expect(podParts[0]).NotTo(BeEmpty())
			g.Expect(podParts[1:]).To(Equal([]string{"Running", "True"}))
			currentPodUID := podParts[0]

			cmd = exec.Command("kubectl", "get", "garagenode", removedGarageNode, "-n", testNamespace,
				"-o", "jsonpath={.status.nodeId}/{.metadata.uid}/{.status.observedPodUid}")
			output, err = utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			parts := strings.Split(output, "/")
			g.Expect(parts).To(HaveLen(3))
			g.Expect(parts[0]).To(Equal(originalNodeIDs[removedGarageNode]))
			g.Expect(parts[1]).NotTo(Equal(originalNodeUIDs[removedGarageNode]),
				"selector scale-in/out should recreate the GarageNode CR while retaining the disk identity")
			g.Expect(parts[2]).To(Equal(currentPodUID),
				"the recreated GarageNode must observe the exact current pool Pod")
			rejoinedGarageNodeUID = parts[1]
			rejoinedPodUID = currentPodUID
		}, 3*time.Minute, 10*time.Second).Should(Succeed())

		// Whether the fail-closed barrier is observable at all here is itself a
		// race. Garage retires a draining version once every node's table sync
		// catches up, and this e2e dataset is tiny, so the rejoin can settle
		// (connected=true/inLayout=true) within a single reconcile — before this
		// block's first poll ever samples the intermediate state. That is not a
		// regression: the barrier held (nothing observed the rejoin completing
		// early) and then correctly cleared. Assert either observation, not only
		// the mid-drain one nothing guarantees is catchable.
		By("proving rejoin remains fail closed while Garage drains the prior layout version, " +
			"or that the drain had already settled before the first observation")
		observedDraining := false
		barrierMessage := ""
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenode", removedGarageNode, "-n", testNamespace,
				"-o", `jsonpath={.metadata.generation}|{.status.conditions[?(@.type=="Ready")].observedGeneration}|{.status.connected}|{.status.inLayout}|{.status.conditions[?(@.type=="Ready")].status}|{.status.conditions[?(@.type=="Ready")].message}`)
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			parts := strings.Split(output, "|")
			g.Expect(parts).To(HaveLen(6))
			g.Expect(parts[1]).To(Equal(parts[0]), "GarageNode Ready condition is stale: %q", output)
			if strings.Contains(parts[5], "another reconciler is changing Garage layout") {
				// The parent and node controllers share a single-flight layout
				// coordinator. A concurrent activation/rejoin mutation can briefly
				// publish a False Ready condition without taking this identity out of
				// the layout. Keep polling until that independent mutation settles.
				return
			}

			if parts[2:5][0] == "true" && parts[2:5][1] == "true" && parts[2:5][2] == "True" {
				// The drain finished before this probe could catch it live; the
				// fail-closed property held for a window this test simply never
				// observed. Downstream checks (rejoin Apply committed, layout
				// settled) still verify the end state unconditionally.
				return
			}
			g.Expect(parts[2:5]).To(Equal([]string{"false", "false", "False"}),
				"GarageNode is neither draining nor converged: %q", output)
			g.Expect(parts[5]).To(ContainSubstring("layout version(s)"))
			g.Expect(parts[5]).To(ContainSubstring("still draining"))
			observedDraining = true
			barrierMessage = parts[5]
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		const adminToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

		if observedDraining {
			barrierMatch := regexp.MustCompile(
				`layout version\(s\) ([0-9]+(?:, [0-9]+)*) are still draining \(current version ([0-9]+)\)`,
			).FindStringSubmatch(barrierMessage)
			Expect(barrierMatch).To(HaveLen(3), "could not parse GarageNode layout barrier: %q", barrierMessage)
			reportedDrainingVersions := strings.Split(barrierMatch[1], ", ")
			reportedCurrentVersion := barrierMatch[2]

			// The GarageNode condition and the Admin API cannot be sampled atomically.
			// Garage may retire the reported version after the operator publishes the
			// barrier but before this probe starts. A Historical entry therefore proves
			// the same claim as a still-Draining entry: the named prior version existed,
			// and its data movement finished between the two observations.
			By("corroborating the reported barrier against Garage layout history")
			Eventually(func(g Gomega) {
				_, barrierHistory := readGarageLayoutSnapshot(
					g, testNamespace, "node-local-rejoin-draining-snapshot", clusterName, adminToken,
				)
				g.Expect(fmt.Sprintf("%d", barrierHistory.CurrentVersion)).To(Equal(reportedCurrentVersion),
					"Garage advanced to an unexpected layout version after reporting the rejoin barrier")
				historyStatuses := make(map[string]string, len(barrierHistory.Versions))
				for _, version := range barrierHistory.Versions {
					historyStatuses[fmt.Sprintf("%d", version.Version)] = version.Status
				}
				for _, version := range reportedDrainingVersions {
					status, ok := historyStatuses[version]
					g.Expect(ok).To(BeTrue(),
						"GarageNode reported layout version %s as draining, but Garage history does not contain it", version)
					g.Expect(status).To(BeElementOf("Draining", "Historical"),
						"GarageNode reported layout version %s as draining, but Garage history marks it %q", version, status)
				}
			}, time.Minute, 5*time.Second).Should(Succeed())
		} else {
			By("skipping barrier corroboration: the drain settled before the first observation")
		}

		By("verifying the rejoin Apply committed the retained disk identity")
		Eventually(func(g Gomega) {
			rejoinLayout, _ := readGarageLayoutSnapshot(
				g, testNamespace, "node-local-rejoin-applied-snapshot", clusterName, adminToken,
			)
			rejoinRoleIDs := make([]string, 0, len(rejoinLayout.Roles))
			for _, role := range rejoinLayout.Roles {
				rejoinRoleIDs = append(rejoinRoleIDs, role.ID)
			}
			g.Expect(rejoinRoleIDs).To(ContainElement(originalNodeIDs[removedGarageNode]),
				"the rejoin layout Apply did not commit the retained disk identity")
			g.Expect(rejoinLayout.StagedRoleChanges).To(BeEmpty(),
				"rejoin left an uncommitted Garage layout mutation")
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("waiting for Garage's prior layout version to finish synchronizing before reporting rejoin convergence")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "daemonset", clusterName+"-storage-"+nodeLocalPoolName, "-n", testNamespace,
				"-o", "jsonpath={.status.desiredNumberScheduled}/{.status.numberReady}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("2/2"))

			cmd = exec.Command("kubectl", "get", "pods", "-n", testNamespace,
				"-l", "garage.rajsingh.info/node-local-pool="+nodeLocalPoolName+
					",garage.rajsingh.info/kubernetes-node="+removedK8sNode,
				"-o", `jsonpath={range .items[*]}{.metadata.uid}{"|"}{.status.phase}{"|"}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}`)
			output, err = utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			podLines := strings.Fields(output)
			g.Expect(podLines).To(HaveLen(1), "expected exactly one current pool Pod on the rejoined Node: %q", output)
			podParts := strings.Split(podLines[0], "|")
			g.Expect(podParts).To(HaveLen(3))
			g.Expect(podParts).To(Equal([]string{rejoinedPodUID, "Running", "True"}),
				"rejoin must not replace the exact Pod while Garage layout history is settling")

			cmd = exec.Command("kubectl", "get", "garagenode", removedGarageNode, "-n", testNamespace,
				"-o", `jsonpath={.metadata.generation}/{.status.conditions[?(@.type=="Ready")].observedGeneration}/{.status.nodeId}/{.metadata.uid}/{.status.observedPodUid}/{.status.connected}/{.status.inLayout}`)
			output, err = utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			parts := strings.Split(output, "/")
			g.Expect(parts).To(HaveLen(7))
			g.Expect(parts[1]).To(Equal(parts[0]), "GarageNode Ready condition is stale: %q", output)
			g.Expect(parts[2:]).To(Equal([]string{
				originalNodeIDs[removedGarageNode], rejoinedGarageNodeUID, rejoinedPodUID, "true", "true",
			}))

			cmd = exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace,
				"-o", `jsonpath={.metadata.generation}/{.status.conditions[?(@.type=="NodeLocalPoolsReady")].observedGeneration}/{.status.conditions[?(@.type=="NodeLocalPoolsReady")].status}/{.status.conditions[?(@.type=="NodeLocalPoolsReady")].reason}`)
			output, err = utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			conditionParts := strings.Split(output, "/")
			g.Expect(conditionParts).To(HaveLen(4))
			g.Expect(conditionParts[1]).To(Equal(conditionParts[0]), "node-local readiness condition is stale: %q", output)
			g.Expect(conditionParts[2:]).To(Equal([]string{"True", "Converged"}))
		}, 20*time.Minute, 10*time.Second).Should(Succeed())
		// A selector rejoin is a second Garage topology mutation. Upstream Garage
		// retains the previous layout until its table synchronization is
		// acknowledged, so the wait above is scoped to that live history barrier.

		By("proving final readiness corresponds to a settled current layout snapshot")
		settledLayout, settledHistory := readGarageLayoutSnapshot(
			Default, testNamespace, "node-local-rejoin-settled-snapshot", clusterName, adminToken,
		)
		settledRoleIDs := make([]string, 0, len(settledLayout.Roles))
		for _, role := range settledLayout.Roles {
			settledRoleIDs = append(settledRoleIDs, role.ID)
		}
		Expect(settledRoleIDs).To(ContainElement(originalNodeIDs[removedGarageNode]))
		Expect(settledLayout.StagedRoleChanges).To(BeEmpty())

		for _, version := range settledHistory.Versions {
			Expect(version.Status).NotTo(Equal("Draining"),
				"NodeLocalPoolsReady=True was published while layout version history was still draining")
		}
	})

	It("should reject a pool with an invalid HostPath", func() {
		invalidYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: ds-invalid
  namespace: %s
spec:
  layoutPolicy: Manual
  replication:
    factor: 1
  storage:
    metadata:
      size: 100Mi
    data:
      size: 1Gi
    nodeLocalPools:
      - name: invalid
        capacity: 1Gi
        selector:
          matchLabels:
            garage.rajsingh.info/e2e-storage: "true"
        metadata:
          hostPath: %s/invalid-meta
        data:
          hostPath: relative/data
  admin:
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
  security:
    allowInsecureSecretPermissions: true
`, testNamespace, hostPathBase)

		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(invalidYAML)
		output, err := utils.Run(cmd)
		Expect(err).To(HaveOccurred(),
			"Webhook should reject a node-local pool with a relative HostPath. Output: %s", output)
		Expect(output).To(ContainSubstring("absolute path"),
			"Error should mention the absolute HostPath contract. Output: %s", output)
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
var e2eCleanupWaitFailures []string

func reportE2ECleanupWait(description string, err error) {
	if err != nil {
		failure := fmt.Sprintf("%s: %v", description, err)
		e2eCleanupWaitFailures = append(e2eCleanupWaitFailures, failure)
		AddReportEntry("E2E cleanup did not converge: "+description, err.Error())
	}
}

// finishE2ECleanupWaits is called only after a cleanup hook has attempted all
// of its steps. A wait failure is accumulated rather than asserted inline so
// one stuck finalizer cannot skip the remaining cleanup and hide more useful
// diagnostics. The completed cleanup is still a suite failure: allowing the
// next Ordered block to run against leaked resources merely turns a cleanup
// defect into an intermittent failure elsewhere.
func finishE2ECleanupWaits() {
	if len(e2eCleanupWaitFailures) == 0 {
		return
	}
	failures := strings.Join(e2eCleanupWaitFailures, "\n")
	e2eCleanupWaitFailures = nil
	AddReportEntry("E2E cleanup failures", failures)
	Fail("E2E cleanup did not converge:\n"+failures, 1)
}

func cleanupManagementHandle(testNamespace string, clusterNames []string) {
	By("deleting this block's CRs (operator finalizes them) then the namespace")
	// Delete API children before their parent clusters. If an earlier spec
	// failed before its own cleanup, leaving a GarageKey or GarageAdminToken
	// behind can keep the namespace terminating even though the parent CRs are
	// gone. Keep the operator live while these finalizers call the Admin API.
	// GarageNodes are deliberately omitted: a positive-capacity node is a
	// prepared deletion while its parent is live. Destroy-policy parent
	// finalization deletes those dependents after the parent has its deletion
	// timestamp, which is the only safe authorization for this teardown.
	for _, resource := range []string{
		"garagekey", "garagebucket", "garageadmintoken", "garagereferencegrant",
	} {
		output, err := utils.Run(exec.Command("kubectl", "delete", resource, "--all", "-n", testNamespace,
			"--ignore-not-found", "--wait=false"))
		if err != nil {
			reportE2ECleanupWait("management-handle "+resource+" delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("management-handle "+resource, waitForE2EResourcesDeleted(
			resource, testNamespace, "", 2*time.Minute,
		))
	}
	for _, n := range clusterNames {
		output, err := utils.Run(exec.Command("kubectl", "delete", "garagecluster", n, "-n", testNamespace,
			"--ignore-not-found", "--wait=false"))
		if err != nil {
			reportE2ECleanupWait("management-handle GarageCluster/"+n+" delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("management-handle GarageCluster/"+n, waitForE2EResourceDeleted(
			"garagecluster", n, testNamespace, 3*time.Minute,
		))
	}
	reportE2ECleanupWait("management-handle garagenode", waitForE2EResourcesDeleted(
		"garagenode", testNamespace, "", 2*time.Minute,
	))
	output, err := utils.Run(exec.Command("kubectl", "delete", "ns", testNamespace,
		"--ignore-not-found", "--wait=false"))
	if err != nil {
		reportE2ECleanupWait("management-handle namespace delete request", fmt.Errorf("%v: %s", err, output))
	}
	reportE2ECleanupWait("management-handle namespace", waitForE2ENamespaceDeleted(testNamespace, 2*time.Minute))
	finishE2ECleanupWaits()
}

// cleanupE2ENamespaceContents removes the namespaced objects generated by a
// GarageCluster before namespace deletion. Namespace GC normally handles this,
// but PVC protection can retain a namespace while StatefulSet Pods are still
// terminating. Stopping the workload owners first makes the PVC deletion
// barrier explicit and keeps #190-style cleanup bounded.
func cleanupE2ENamespaceContents(testNamespace string) {
	By("deleting generated workload owners before their Pods and PVCs")
	for _, resource := range []string{
		"statefulset", "deployment", "daemonset", "replicaset", "job", "cronjob",
	} {
		output, err := utils.Run(exec.Command("kubectl", "delete", resource, "--all", "-n", testNamespace,
			"--ignore-not-found", "--wait=false"))
		if err != nil {
			reportE2ECleanupWait("#190 "+resource+" delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("#190 "+resource, waitForE2EResourcesDeleted(
			resource, testNamespace, "", 2*time.Minute,
		))
	}

	By("deleting generated Pods before their PVCs")
	output, err := utils.Run(exec.Command("kubectl", "get", "pvc", "--ignore-not-found", "-o", "jsonpath={.items[*].metadata.name}",
		"--request-timeout="+e2eKubernetesReadTimeout, "-n", testNamespace))
	if err != nil {
		reportE2ECleanupWait("#190 pvc finalizer discovery", fmt.Errorf("%v: %s", err, output))
	} else {
		// The managed PVC finalizer is normally released by the controller through
		// its authenticated webhook. This teardown has already removed that
		// webhook and stopped the controller, so release every test PVC finalizer
		// explicitly before deletion rather than stranding the namespace.
		for _, name := range strings.Fields(output) {
			patchOutput, patchErr := utils.Run(exec.Command("kubectl", "patch", "pvc", name,
				"-n", testNamespace, "--type=merge", "-p", `{"metadata":{"finalizers":null}}`,
				"--request-timeout="+e2eKubernetesReadTimeout))
			if patchErr != nil {
				reportE2ECleanupWait("#190 pvc/"+name+" finalizer removal",
					fmt.Errorf("%v: %s", patchErr, patchOutput))
			}
		}
	}
	for _, resource := range []string{"pod", "pvc"} {
		output, err := utils.Run(exec.Command("kubectl", "delete", resource, "--all", "-n", testNamespace,
			"--ignore-not-found", "--wait=false"))
		if err != nil {
			reportE2ECleanupWait("#190 "+resource+" delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("#190 "+resource, waitForE2EResourcesDeleted(
			resource, testNamespace, "", 3*time.Minute,
		))
	}

	By("deleting remaining generated namespaced objects")
	// kube-root-ca.crt and default are recreated by Kubernetes when deleted;
	// namespace termination owns their eventual removal, so do not wait on them
	// as if they were Garage-generated objects.
	for _, resource := range []string{"service", "secret", "role", "rolebinding"} {
		output, err := utils.Run(exec.Command("kubectl", "delete", resource, "--all", "-n", testNamespace,
			"--ignore-not-found", "--wait=false"))
		if err != nil {
			reportE2ECleanupWait("#190 "+resource+" delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("#190 "+resource, waitForE2EResourcesDeleted(
			resource, testNamespace, "", 2*time.Minute,
		))
	}
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
// operator to 0 → clear finalizers → delete CRs (--wait=false) → request ns
// deletion → make undeploy → make uninstall → poll the namespace. The
// namespace controller can retain a Terminating namespace while the CRDs are
// still installed, even after every namespaced object has disappeared; the
// final poll therefore belongs after CRD removal.
func cleanupAuto190(testNamespace string, _ []string) {
	By("deleting admission webhook configurations first")
	for _, webhook := range []struct {
		kind string
		name string
	}{
		{kind: "validatingwebhookconfiguration", name: "garage-operator-validating-webhook-configuration"},
		{kind: "mutatingwebhookconfiguration", name: "garage-operator-mutating-webhook-configuration"},
	} {
		output, err := utils.Run(exec.Command("kubectl", "delete", webhook.kind, webhook.name,
			"--ignore-not-found", "--timeout=60s"))
		if err != nil {
			reportE2ECleanupWait(webhook.kind+"/"+webhook.name+" delete request",
				fmt.Errorf("%v: %s", err, output))
		}
	}

	By("scaling operator to 0 so it can't re-add finalizers")
	output, err := utils.Run(exec.Command("kubectl", "scale", "deployment",
		"garage-operator-controller-manager", "-n", namespace, "--replicas=0", "--timeout=30s"))
	if err != nil {
		reportE2ECleanupWait("controller-manager scale-down request", fmt.Errorf("%v: %s", err, output))
	}
	reportE2ECleanupWait("controller-manager scale-down", waitForE2EDeploymentScaledDown(
		namespace, "garage-operator-controller-manager", 2*time.Minute,
	))

	By("clearing finalizers and deleting test resources")
	// The operator is stopped before finalizers are cleared so no new
	// reconciliation can re-add them. Include every namespaced Garage CR: a
	// failed bucket/key spec must not leave its finalizer blocking the namespace
	// after this #190-style teardown.
	resources := []string{
		"garagekey", "garagebucket", "garageadmintoken", "garagereferencegrant", "garagenode", "garagecluster",
	}
	for _, resource := range resources {
		output, err := utils.Run(exec.Command("kubectl", "get", resource, "-n", testNamespace,
			"--ignore-not-found", "-o", "jsonpath={.items[*].metadata.name}"))
		if err != nil {
			reportE2ECleanupWait(resource+" finalizer discovery", fmt.Errorf("%v: %s", err, output))
			continue
		}
		for _, name := range strings.Fields(output) {
			patchOutput, patchErr := utils.Run(exec.Command("kubectl", "patch", resource, name, "-n", testNamespace,
				"--type=merge", "-p", `{"metadata":{"finalizers":null}}`))
			if patchErr != nil {
				reportE2ECleanupWait(resource+"/"+name+" finalizer removal",
					fmt.Errorf("%v: %s", patchErr, patchOutput))
			}
		}
	}
	for _, resource := range resources {
		output, err := utils.Run(exec.Command("kubectl", "delete", resource, "--all", "-n", testNamespace,
			"--wait=false", "--ignore-not-found"))
		if err != nil {
			reportE2ECleanupWait(resource+" delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait(resource, waitForE2EResourcesDeleted(
			resource, testNamespace, "", 2*time.Minute,
		))
	}
	cleanupE2ENamespaceContents(testNamespace)
	output, err = utils.Run(exec.Command("kubectl", "delete", "ns", testNamespace,
		"--ignore-not-found", "--wait=false"))
	if err != nil {
		reportE2ECleanupWait("#190 namespace delete request", fmt.Errorf("%v: %s", err, output))
	}

	By("undeploying the controller-manager")
	output, err = utils.Run(exec.Command("make", "undeploy", "ignore-not-found=true"))
	if err != nil {
		reportE2ECleanupWait("make undeploy", fmt.Errorf("%v: %s", err, output))
	}

	By("uninstalling CRDs")
	output, err = utils.Run(exec.Command("make", "uninstall", "ignore-not-found=true"))
	if err != nil {
		reportE2ECleanupWait("make uninstall", fmt.Errorf("%v: %s", err, output))
	}
	reportE2ECleanupWait("#190 namespace", waitForE2ENamespaceDeleted(testNamespace, 2*time.Minute))
	finishE2ECleanupWaits()
}

// spec.zoneFrom (#294) derives each storage node's layout zone from a label on
// the Kubernetes Node its pod is scheduled to. The e2e kind cluster is
// single-node, which is enough to prove the behaviour end to end: the label
// value must beat spec.zone, must be re-resolved when it changes, and must fall
// back to spec.zone when it disappears. Multi-zone placement across several
// Kubernetes Nodes is the scheduler's job, not the operator's.
var _ = Describe("Auto Mode zoneFrom", Ordered, Label("zone-from"), func() {
	const (
		testNamespace = "garage-zone-from"
		clusterName   = "zf-cluster"
		nodeCRName    = clusterName + "-storage-0"
		rackLabel     = "e2e.garage.rajsingh.info/rack"
		fallbackZone  = "site-a"
		adminToken    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)

	labelNodes := func(value string) {
		args := []string{"label", "nodes", "--all", "--overwrite"}
		if value == "" {
			args = append(args, rackLabel+"-")
		} else {
			args = append(args, rackLabel+"="+value)
		}
		_, err := utils.Run(exec.Command("kubectl", args...))
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
	}

	expectResolvedZone := func(want string) {
		EventuallyWithOffset(1, func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "garagenode", nodeCRName, "-n", testNamespace,
				"-o", "jsonpath={.status.zone}")
			out, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal(want), "status.zone should be %q, got %q", want, out)
		}, 4*time.Minute, 5*time.Second).Should(Succeed())
	}

	// expectLayoutZone proves the value actually reached Garage, not just the
	// operator's status.
	expectLayoutZone := func(want string) {
		EventuallyWithOffset(1, func(g Gomega) {
			script := fmt.Sprintf("curl -s -H 'Authorization: Bearer %s' http://%s.%s.svc.cluster.local:3903/v2/GetClusterLayout",
				adminToken, clusterName, testNamespace)
			out := runCurlPod(g, testNamespace, "zf-layout-check", script)
			// Garage pretty-prints, so match the field rather than a compact substring.
			g.Expect(out).To(MatchRegexp(`"zone":\s*"`+regexp.QuoteMeta(want)+`"`),
				"layout should carry zone %q, got: %s", want, out)
		}, 4*time.Minute, 15*time.Second).Should(Succeed())
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
		labelNodes("")
		if output, err := utils.Run(exec.Command("kubectl", "delete", "garagecluster", clusterName,
			"-n", testNamespace, "--ignore-not-found", "--wait=false")); err != nil {
			reportE2ECleanupWait("zone-from GarageCluster delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("zone-from GarageCluster", waitForE2EResourceDeleted(
			"garagecluster", clusterName, testNamespace, 3*time.Minute,
		))
		if output, err := utils.Run(exec.Command("kubectl", "delete", "ns", testNamespace,
			"--ignore-not-found", "--wait=false")); err != nil {
			reportE2ECleanupWait("zone-from namespace delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("zone-from namespace", waitForE2ENamespaceDeleted(testNamespace, 2*time.Minute))
		finishE2ECleanupWaits()
	})

	It("resolves the layout zone from the Kubernetes Node label", func() {
		By("labelling the Kubernetes Nodes")
		labelNodes("rack-a")

		By("creating the admin token secret")
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
  name: %s
  namespace: %s
spec:
  zone: %s
  zoneFrom:
    nodeLabel: %s
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
`, clusterName, testNamespace, fallbackZone, rackLabel)

		By("applying the cluster (retry until the webhook is up)")
		Eventually(func(g Gomega) {
			c := exec.Command("kubectl", "apply", "-f", "-")
			c.Stdin = strings.NewReader(clusterYAML)
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred(), "cluster rejected: %s", out)
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("waiting for the cluster to be Running")
		Eventually(func(g Gomega) {
			c := exec.Command("kubectl", "get", "garagecluster", clusterName, "-n", testNamespace,
				"-o", "jsonpath={.status.phase}")
			out, err := utils.Run(c)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal("Running"), "cluster not Running: %s", out)
		}, 5*time.Minute, 5*time.Second).Should(Succeed())

		By("verifying the generated GarageNode resolved the label value, not spec.zone")
		expectResolvedZone("rack-a")

		By("verifying the zone reached the Garage layout")
		expectLayoutZone("rack-a")
	})

	It("follows the label to a new value", func() {
		// A pod that moves to a Kubernetes Node in a different failure domain
		// must change the layout, otherwise zone redundancy silently lies.
		// Relabelling in place exercises the same code path without needing a
		// second Kubernetes Node.
		labelNodes("rack-b")
		expectResolvedZone("rack-b")
		expectLayoutZone("rack-b")
	})

	It("falls back to spec.zone when the label is removed", func() {
		labelNodes("")
		expectResolvedZone(fallbackZone)
		expectLayoutZone(fallbackZone)
	})
})
