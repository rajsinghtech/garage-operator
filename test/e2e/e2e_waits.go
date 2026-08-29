//go:build e2e
// +build e2e

/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package e2e

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rajsinghtech/garage-operator/test/utils"
)

const e2eKubernetesReadTimeout = "15s"

// config/default prepends "garage-operator-" to the kubebuilder base name.
const e2eWebhookServiceName = "garage-operator-webhook-service"

type e2eNamespace struct {
	Status struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

type e2eWebhookEndpointSliceList struct {
	Items []struct {
		Endpoints []struct {
			Addresses  []string `json:"addresses"`
			Conditions struct {
				Ready       *bool `json:"ready"`
				Serving     *bool `json:"serving"`
				Terminating *bool `json:"terminating"`
			} `json:"conditions"`
		} `json:"endpoints"`
	} `json:"items"`
}

func e2eNamespacePhase(output string) (string, error) {
	var namespace e2eNamespace
	if err := json.Unmarshal([]byte(stripKubectlWarnings(output)), &namespace); err != nil {
		return "", err
	}
	return namespace.Status.Phase, nil
}

func e2EWebhookServiceHasHTTPS(output string) (bool, error) {
	var service struct {
		Spec struct {
			Ports []struct {
				Port int32 `json:"port"`
			} `json:"ports"`
		} `json:"spec"`
	}
	if err := json.Unmarshal([]byte(stripKubectlWarnings(output)), &service); err != nil {
		return false, err
	}
	for _, port := range service.Spec.Ports {
		if port.Port == 443 {
			return true, nil
		}
	}
	return false, nil
}

func e2EReadyWebhookAddresses(output string) ([]string, error) {
	var endpointSlices e2eWebhookEndpointSliceList
	if err := json.Unmarshal([]byte(stripKubectlWarnings(output)), &endpointSlices); err != nil {
		return nil, err
	}
	addresses := make([]string, 0)
	for _, slice := range endpointSlices.Items {
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready ||
				(endpoint.Conditions.Serving != nil && !*endpoint.Conditions.Serving) ||
				(endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating) {
				continue
			}
			addresses = append(addresses, endpoint.Addresses...)
		}
	}
	sort.Strings(addresses)
	return addresses, nil
}

type e2ePod struct {
	Metadata struct {
		Name              string  `json:"name"`
		DeletionTimestamp *string `json:"deletionTimestamp"`
	} `json:"metadata"`
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		Phase      string `json:"phase"`
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
	} `json:"status"`
}

func e2ePodsForSelector(namespace, selector string) ([]e2ePod, error) {
	output, err := utils.Run(exec.Command("kubectl", "get", "pods",
		"-n", namespace, "-l", selector, "-o", "json",
		"--request-timeout="+e2eKubernetesReadTimeout,
	))
	if err != nil {
		return nil, err
	}
	var podList struct {
		Items []e2ePod `json:"items"`
	}
	if err := json.Unmarshal([]byte(stripKubectlWarnings(output)), &podList); err != nil {
		return nil, fmt.Errorf("decode Pods selected by %q: %w", selector, err)
	}
	return podList.Items, nil
}

func activeE2EPods(pods []e2ePod) []e2ePod {
	active := make([]e2ePod, 0, len(pods))
	for _, pod := range pods {
		if pod.Metadata.DeletionTimestamp == nil && pod.Metadata.Name != "" {
			active = append(active, pod)
		}
	}
	sort.Slice(active, func(i, j int) bool {
		return active[i].Metadata.Name < active[j].Metadata.Name
	})
	return active
}

func e2ePodIsReady(pod e2ePod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == "Ready" && condition.Status == "True" {
			return true
		}
	}
	return false
}

// e2ePodName returns a stable active Pod name. A Ready Pod is preferred so a
// rollout does not accidentally select a newly-created, still-starting Pod;
// requireReady makes the absence of a Ready Pod retryable by callers.
func e2ePodName(namespace, selector string, requireReady bool) (string, error) {
	pods, err := e2ePodsForSelector(namespace, selector)
	if err != nil {
		return "", err
	}
	active := activeE2EPods(pods)
	if len(active) == 0 {
		return "", errors.New("no active Pod matches selector " + selector)
	}
	for _, pod := range active {
		if pod.Status.Phase == "Running" && e2ePodIsReady(pod) {
			return pod.Metadata.Name, nil
		}
	}
	if requireReady {
		return "", errors.New("no Ready active Pod matches selector " + selector)
	}
	return active[0].Metadata.Name, nil
}

// controllerManagerPodName returns a non-terminating controller pod. During a
// Deployment rollout Kubernetes can briefly return both the old and new Pod;
// selecting the first API-list item makes a readiness wait depend on list
// ordering and can keep observing the terminating old Pod until the wait
// expires. Prefer a Ready active Pod, then use a stable name order while it is
// starting.
func controllerManagerPodName(namespace string) (string, error) {
	return e2ePodName(namespace, "control-plane=controller-manager", false)
}

func controllerManagerPodReady(namespace string) (string, error) {
	return e2ePodName(namespace, "control-plane=controller-manager", true)
}

func e2ePodContainerRestartCount(namespace, podName, containerName string) (string, error) {
	output, err := utils.Run(exec.Command("kubectl", "get", "pod", podName,
		"-n", namespace, "-o", "json",
		"--request-timeout="+e2eKubernetesReadTimeout,
	))
	if err != nil {
		return "", err
	}
	var pod struct {
		Status struct {
			ContainerStatuses []struct {
				Name         string `json:"name"`
				RestartCount int32  `json:"restartCount"`
			} `json:"containerStatuses"`
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(stripKubectlWarnings(output)), &pod); err != nil {
		return "", fmt.Errorf("decode Pod/%s: %w", podName, err)
	}
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == containerName {
			return strconv.FormatInt(int64(status.RestartCount), 10), nil
		}
	}
	return "", fmt.Errorf("container %q has no status in Pod/%s", containerName, podName)
}

// pollE2E retries a Kubernetes observation until it succeeds or its bounded
// deadline expires. API errors are retryable because an E2E run commonly
// observes a resource while its namespace, webhook, or controller is rolling
// over.
func pollE2E(timeout, interval time.Duration, observe func() (bool, error)) error {
	if timeout <= 0 {
		return errors.New("E2E wait timeout must be positive")
	}
	if interval <= 0 {
		interval = time.Second
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		done, err := observe()
		if done && err == nil {
			return nil
		}
		if err != nil {
			lastErr = err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if lastErr != nil {
				return lastErr
			}
			return errors.New("condition did not converge before the deadline")
		}
		if interval > remaining {
			interval = remaining
		}
		time.Sleep(interval)
	}
}

// ensureE2ENamespaceActive creates a shared namespace when it is absent and
// refuses to continue if an existing namespace is terminating. Treating every
// create error as "already exists" lets a later Ordered block reuse a broken
// namespace left by an interrupted block.
func ensureE2ENamespaceActive(namespace string) error {
	output, err := utils.Run(exec.Command("kubectl", "get", "namespace", namespace,
		"--ignore-not-found", "-o", "json",
		"--request-timeout="+e2eKubernetesReadTimeout,
	))
	if err != nil {
		return fmt.Errorf("inspect namespace %s: %w", namespace, err)
	}
	if strings.TrimSpace(output) == "" {
		if output, err = utils.Run(exec.Command("kubectl", "create", "namespace", namespace,
			"--request-timeout="+e2eKubernetesReadTimeout,
		)); err != nil {
			return fmt.Errorf("create namespace %s: %v: %s", namespace, err, output)
		}
	}
	return waitForE2ENamespaceActive(namespace, 2*time.Minute)
}

// createE2ETestNamespace is for a block-owned namespace. A namespace that is
// already present may contain PVCs, finalizers, or Garage identities from an
// interrupted run, so silently adopting it would make the first assertion
// depend on stale state.
func createE2ETestNamespace(namespace string) error {
	output, err := utils.Run(exec.Command("kubectl", "get", "namespace", namespace,
		"--ignore-not-found", "-o", "json",
		"--request-timeout="+e2eKubernetesReadTimeout,
	))
	if err != nil {
		return fmt.Errorf("inspect test namespace %s: %w", namespace, err)
	}
	if strings.TrimSpace(output) != "" {
		var existing e2eNamespace
		if err := json.Unmarshal([]byte(stripKubectlWarnings(output)), &existing); err != nil {
			return fmt.Errorf("decode existing test namespace %s: %w", namespace, err)
		}
		return fmt.Errorf("test namespace %s already exists with phase %q; refusing stale fixture", namespace, existing.Status.Phase)
	}
	if output, err = utils.Run(exec.Command("kubectl", "create", "namespace", namespace,
		"--request-timeout="+e2eKubernetesReadTimeout,
	)); err != nil {
		return fmt.Errorf("create test namespace %s: %v: %s", namespace, err, output)
	}
	return waitForE2ENamespaceActive(namespace, 2*time.Minute)
}

func waitForE2ENamespaceActive(namespace string, timeout time.Duration) error {
	return pollE2E(timeout, time.Second, func() (bool, error) {
		output, err := utils.Run(exec.Command("kubectl", "get", "namespace", namespace,
			"--ignore-not-found", "-o", "json",
			"--request-timeout="+e2eKubernetesReadTimeout,
		))
		if err != nil {
			return false, err
		}
		if strings.TrimSpace(output) == "" {
			return false, fmt.Errorf("namespace %s is not present", namespace)
		}
		phase, err := e2eNamespacePhase(output)
		if err != nil {
			return false, fmt.Errorf("decode namespace %s: %w", namespace, err)
		}
		switch phase {
		case "Active":
			return true, nil
		case "Terminating":
			return false, fmt.Errorf("namespace %s is terminating", namespace)
		default:
			return false, nil
		}
	})
}

// waitForE2EWebhookRoute waits for the Service and its ready EndpointSlice
// before callers submit a CR. Pod readiness proves that the webhook listener
// is running, but the API server can observe that event before EndpointSlice
// updates and kube-proxy routing have caught up.
func waitForE2EWebhookRoute(namespace string, timeout time.Duration) error {
	return waitForE2EWebhookServiceRoute(namespace, e2eWebhookServiceName, timeout)
}

func waitForE2EWebhookServiceRoute(namespace, serviceName string, timeout time.Duration) error {
	var lastAddresses string
	stablePolls := 0
	deadline := time.Now().Add(timeout)
	context := ""
	if cluster := strings.TrimSpace(os.Getenv("KIND_CLUSTER")); cluster != "" {
		context = "kind-" + cluster
	}
	projectDir, err := utils.GetProjectDir()
	if err != nil {
		return fmt.Errorf("resolve repository root for webhook route probe: %w", err)
	}
	webhookProbe := filepath.Join(projectDir, "hack", "wait-for-operator-webhook.sh")
	return pollE2E(timeout, 2*time.Second, func() (bool, error) {
		serviceOutput, err := utils.Run(exec.Command("kubectl", "get", "service", serviceName,
			"-n", namespace, "-o", "json",
			"--request-timeout="+e2eKubernetesReadTimeout,
		))
		if err != nil {
			return false, err
		}
		hasHTTPS, err := e2EWebhookServiceHasHTTPS(serviceOutput)
		if err != nil {
			return false, fmt.Errorf("decode webhook Service: %w", err)
		}
		if !hasHTTPS {
			return false, fmt.Errorf("webhook Service %s/%s has no port 443", namespace, serviceName)
		}

		endpointOutput, err := utils.Run(exec.Command("kubectl", "get", "endpointslice",
			"-n", namespace, "-l", "kubernetes.io/service-name="+serviceName,
			"-o", "json", "--request-timeout="+e2eKubernetesReadTimeout,
		))
		if err != nil {
			return false, err
		}
		addresses, err := e2EReadyWebhookAddresses(endpointOutput)
		if err != nil {
			return false, fmt.Errorf("decode webhook EndpointSlices: %w", err)
		}
		if len(addresses) == 0 {
			lastAddresses = ""
			stablePolls = 0
			return false, nil
		}
		currentAddresses := strings.Join(addresses, ",")
		if currentAddresses == lastAddresses {
			stablePolls++
		} else {
			lastAddresses = currentAddresses
			stablePolls = 1
		}
		if stablePolls < 2 {
			return false, nil
		}

		// EndpointSlice publication is necessary but does not prove that
		// kube-proxy has installed the Service route yet. The shared shell
		// helper performs a bounded port-forward + HTTP probe against this
		// exact Service and is also used by the shell E2E drivers.
		remaining := time.Until(deadline)
		remainingSeconds := int(remaining / time.Second)
		if remainingSeconds < 1 {
			return false, errors.New("webhook Service route wait deadline expired")
		}
		probe := exec.Command(webhookProbe, context, serviceName, namespace,
			strconv.Itoa(remainingSeconds))
		if output, err := utils.Run(probe); err != nil {
			return false, fmt.Errorf("probe webhook Service route: %v: %s", err, output)
		}
		return true, nil
	})
}

func waitForE2EResourceDeleted(resource, name, namespace string, timeout time.Duration) error {
	return pollE2E(timeout, time.Second, func() (bool, error) {
		args := []string{"get", resource, name, "--ignore-not-found", "-o", "name",
			"--request-timeout=" + e2eKubernetesReadTimeout}
		if namespace != "" {
			args = append(args, "-n", namespace)
		}
		output, err := utils.Run(exec.Command("kubectl", args...))
		if err != nil {
			return false, err
		}
		return strings.TrimSpace(output) == "", nil
	})
}

func waitForE2EResourcesDeleted(resource, namespace, selector string, timeout time.Duration) error {
	return pollE2E(timeout, time.Second, func() (bool, error) {
		args := []string{"get", resource, "--ignore-not-found", "-o", "name",
			"--request-timeout=" + e2eKubernetesReadTimeout}
		if namespace != "" {
			args = append(args, "-n", namespace)
		}
		if selector != "" {
			args = append(args, "-l", selector)
		}
		output, err := utils.Run(exec.Command("kubectl", args...))
		if err != nil {
			return false, err
		}
		return strings.TrimSpace(output) == "", nil
	})
}

func waitForE2ENamespaceDeleted(namespace string, timeout time.Duration) error {
	return pollE2E(timeout, time.Second, func() (bool, error) {
		output, err := utils.Run(exec.Command("kubectl", "get", "namespace", namespace,
			"--ignore-not-found", "-o", "name",
			"--request-timeout="+e2eKubernetesReadTimeout,
		))
		if err != nil {
			return false, err
		}
		return strings.TrimSpace(output) == "", nil
	})
}

// waitForE2EDeploymentScaledDown waits for both the desired replica count and
// the observed Deployment status. Waiting only for spec.replicas=0 allows the
// old operator process to keep reconciling while teardown patches finalizers;
// status can also briefly report zero while a terminating Pod still exists.
func waitForE2EDeploymentScaledDown(namespace, name string, timeout time.Duration) error {
	return pollE2E(timeout, time.Second, func() (bool, error) {
		output, err := utils.Run(exec.Command("kubectl", "get", "deployment", name,
			"-n", namespace, "--ignore-not-found", "-o", "json",
			"--request-timeout="+e2eKubernetesReadTimeout,
		))
		if err != nil {
			return false, err
		}
		deploymentScaledDown := false
		if strings.TrimSpace(output) == "" {
			deploymentScaledDown = true
		} else {
			var deployment struct {
				Spec struct {
					Replicas *int32 `json:"replicas"`
				} `json:"spec"`
				Status struct {
					Replicas    int32 `json:"replicas"`
					Updated     int32 `json:"updatedReplicas"`
					Ready       int32 `json:"readyReplicas"`
					Available   int32 `json:"availableReplicas"`
					Unavailable int32 `json:"unavailableReplicas"`
					Terminating int32 `json:"terminatingReplicas"`
				} `json:"status"`
			}
			if err := json.Unmarshal([]byte(stripKubectlWarnings(output)), &deployment); err != nil {
				return false, fmt.Errorf("decode Deployment/%s: %w", name, err)
			}
			deploymentScaledDown = deployment.Spec.Replicas != nil && *deployment.Spec.Replicas == 0 &&
				deployment.Status.Replicas == 0 && deployment.Status.Updated == 0 &&
				deployment.Status.Ready == 0 && deployment.Status.Available == 0 &&
				deployment.Status.Unavailable == 0 && deployment.Status.Terminating == 0
		}
		if !deploymentScaledDown {
			return false, nil
		}

		// The Deployment status is not a complete termination barrier. Verify
		// that no old or terminating controller Pod remains before finalizers
		// are patched; otherwise it can still issue Garage API calls during
		// teardown.
		pods, err := e2ePodsForSelector(namespace,
			"control-plane=controller-manager,app.kubernetes.io/name=garage-operator")
		if err != nil {
			return false, err
		}
		for _, pod := range pods {
			if pod.Metadata.Name != "" {
				return false, nil
			}
		}
		return true, nil
	})
}
