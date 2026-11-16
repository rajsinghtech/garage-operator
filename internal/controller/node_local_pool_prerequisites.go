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

package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/discovery"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

const (
	minimumNodeLocalPoolKubernetesMajor = 1
	minimumNodeLocalPoolKubernetesMinor = 27
	nodeLocalPoolCapabilityGateName     = "garage.rajsingh.info/node-local-pool-capability"
	nodeLocalPoolCapabilityEvidenceTTL  = 30 * time.Second
	nodeLocalPoolSchedulerProbeTimeout  = 30 * time.Second
	nodeLocalPoolSchedulerProbeRetry    = time.Second
	nodeLocalPoolCapabilityProbeLabel   = "garage.rajsingh.info/node-local-capability-probe"
	nodeLocalPoolCapabilityProbeUID     = "garage.rajsingh.info/node-local-capability-cluster-uid"
	nodeLocalPoolCapabilityProbeApp     = "garage-node-local-capability-probe"
)

// NodeLocalPoolPrerequisiteResult is the fail-closed capability decision made
// before a node-local workload or its Kubernetes Node activation state may be
// changed.
type NodeLocalPoolPrerequisiteResult struct {
	Supported  bool
	Reason     string
	Message    string
	RetryAfter time.Duration

	// evidenceObservedAt is the kube-scheduler condition timestamp behind a
	// successful decision. Keep it internal: callers only need the decision,
	// while the checker uses the timestamp to ensure the shared TTL starts at
	// the underlying observation rather than after API reads and cleanup.
	evidenceObservedAt time.Time
}

// NodeLocalPoolPrerequisiteChecker verifies the API-server and kube-scheduler
// behavior required by the node-local membership safety protocol. Version
// alone is insufficient: Pod scheduling gates were independently feature-gated
// in those components on Kubernetes 1.27 through 1.29.
type NodeLocalPoolPrerequisiteChecker interface {
	Check(context.Context, *garagev1beta2.GarageCluster) NodeLocalPoolPrerequisiteResult
}

type nodeLocalPoolPrerequisiteChecker struct {
	client        client.Client
	reader        client.Reader
	serverVersion discovery.ServerVersionInterface
	now           func() time.Time
	evidenceTTL   time.Duration

	mu       sync.RWMutex
	evidence map[string]nodeLocalPoolCapabilityEvidence
}

type nodeLocalPoolCapabilityEvidence struct {
	observedServerVersion string
	observedAt            time.Time
	expiresAt             time.Time
}

type nodeLocalPoolPrerequisiteSessionContextKey struct{}

// nodeLocalPoolPrerequisiteSession pins successful evidence for one
// GarageCluster Reconcile call. The shared evidence cache is deliberately
// short-lived so a control-plane change is detected quickly, but expiry in the
// middle of a long reconciliation must not introduce a second probe after the
// same pass has already started mutating activation state.
type nodeLocalPoolPrerequisiteSession struct {
	mu       sync.RWMutex
	evidence map[string]nodeLocalPoolCapabilityEvidence
}

// NewNodeLocalPoolPrerequisiteChecker constructs the cluster capability probe
// used by GarageCluster reconciliation. Only successful evidence is cached so
// a control-plane upgrade or feature-gate correction can unblock later passes.
func NewNodeLocalPoolPrerequisiteChecker(
	k8sClient client.Client,
	apiReader client.Reader,
	serverVersion discovery.ServerVersionInterface,
) NodeLocalPoolPrerequisiteChecker {
	if apiReader == nil {
		apiReader = k8sClient
	}
	return &nodeLocalPoolPrerequisiteChecker{
		client:        k8sClient,
		reader:        apiReader,
		serverVersion: serverVersion,
		now:           time.Now,
		evidenceTTL:   nodeLocalPoolCapabilityEvidenceTTL,
		evidence:      make(map[string]nodeLocalPoolCapabilityEvidence),
	}
}

func withNodeLocalPoolPrerequisiteSession(ctx context.Context) context.Context {
	if _, ok := ctx.Value(nodeLocalPoolPrerequisiteSessionContextKey{}).(*nodeLocalPoolPrerequisiteSession); ok {
		return ctx
	}
	return context.WithValue(ctx, nodeLocalPoolPrerequisiteSessionContextKey{}, &nodeLocalPoolPrerequisiteSession{
		evidence: make(map[string]nodeLocalPoolCapabilityEvidence),
	})
}

func nodeLocalPoolPrerequisiteSessionEvidence(
	ctx context.Context,
	key string,
) (nodeLocalPoolCapabilityEvidence, bool) {
	session, ok := ctx.Value(nodeLocalPoolPrerequisiteSessionContextKey{}).(*nodeLocalPoolPrerequisiteSession)
	if !ok || session == nil {
		return nodeLocalPoolCapabilityEvidence{}, false
	}
	session.mu.RLock()
	evidence, found := session.evidence[key]
	session.mu.RUnlock()
	return evidence, found
}

func rememberNodeLocalPoolPrerequisiteSessionEvidence(
	ctx context.Context,
	key string,
	evidence nodeLocalPoolCapabilityEvidence,
) {
	session, ok := ctx.Value(nodeLocalPoolPrerequisiteSessionContextKey{}).(*nodeLocalPoolPrerequisiteSession)
	if !ok || session == nil {
		return
	}
	session.mu.Lock()
	session.evidence[key] = evidence
	session.mu.Unlock()
}

func supportedNodeLocalPoolCapability(
	namespace string,
	evidence nodeLocalPoolCapabilityEvidence,
	pinnedForReconcile bool,
) NodeLocalPoolPrerequisiteResult {
	if pinnedForReconcile {
		return NodeLocalPoolPrerequisiteResult{
			Supported: true,
			Message: fmt.Sprintf(
				"Kubernetes %s API and scheduler honor Pod scheduling gates in namespace %s (evidence observed at %s and pinned for this reconciliation)",
				evidence.observedServerVersion, namespace,
				evidence.observedAt.UTC().Format(time.RFC3339),
			),
		}
	}
	return NodeLocalPoolPrerequisiteResult{
		Supported: true,
		Message: fmt.Sprintf(
			"Kubernetes %s API and scheduler honor Pod scheduling gates in namespace %s (evidence valid until %s)",
			evidence.observedServerVersion, namespace,
			evidence.expiresAt.UTC().Format(time.RFC3339),
		),
	}
}

func (c *nodeLocalPoolPrerequisiteChecker) Check(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) NodeLocalPoolPrerequisiteResult {
	if cluster == nil || cluster.Namespace == "" || cluster.Name == "" || cluster.UID == "" {
		return unknownNodeLocalPoolCapability("GarageCluster name, namespace, and UID are required for a scheduler capability probe")
	}
	namespace := cluster.Namespace
	// Admission policy can vary by namespace, while API-server and scheduler
	// behavior is otherwise shared. Reuse one recent positive proof among
	// GarageClusters in the same namespace, never across namespaces.
	evidenceKey := namespace
	now := c.now()
	if evidence, found := nodeLocalPoolPrerequisiteSessionEvidence(ctx, evidenceKey); found {
		return supportedNodeLocalPoolCapability(namespace, evidence, true)
	}
	c.mu.RLock()
	evidence, found := c.evidence[evidenceKey]
	if found && now.Before(evidence.expiresAt) {
		c.mu.RUnlock()
		rememberNodeLocalPoolPrerequisiteSessionEvidence(ctx, evidenceKey, evidence)
		return supportedNodeLocalPoolCapability(namespace, evidence, false)
	}
	c.mu.RUnlock()

	if c.serverVersion == nil {
		return unknownNodeLocalPoolCapability("Kubernetes discovery client is not configured")
	}
	serverInfo, err := c.serverVersion.ServerVersion()
	if err != nil {
		return unknownNodeLocalPoolCapability(fmt.Sprintf("reading Kubernetes server version: %v", err))
	}
	major, minor, displayVersion, err := parseKubernetesServerVersion(serverInfo)
	if err != nil {
		return unknownNodeLocalPoolCapability(err.Error())
	}
	if major < minimumNodeLocalPoolKubernetesMajor ||
		(major == minimumNodeLocalPoolKubernetesMajor && minor < minimumNodeLocalPoolKubernetesMinor) {
		return NodeLocalPoolPrerequisiteResult{
			Reason: garagev1beta1.ReasonNodeLocalPoolUnsupportedKubernetesVersion,
			Message: fmt.Sprintf(
				"spec.storage.nodeLocalPools requires Kubernetes 1.27 or newer; detected %s; no node-local DaemonSet or Kubernetes Node activation state was changed",
				displayVersion,
			),
		}
	}
	if c.client == nil {
		return unknownNodeLocalPoolCapability("Kubernetes capability-probe client is not configured")
	}
	probe := nodeLocalPoolSchedulingGateDaemonSetProbe(namespace)
	if err := c.client.Create(ctx, probe, &client.CreateOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
		if apierrors.IsInvalid(err) || apierrors.IsBadRequest(err) || apierrors.IsNotFound(err) ||
			apierrors.IsMethodNotSupported(err) {
			return NodeLocalPoolPrerequisiteResult{
				Reason: garagev1beta1.ReasonNodeLocalPoolSchedulingGatesUnavailable,
				Message: fmt.Sprintf(
					"Kubernetes %s rejected the node-local DaemonSet scheduling-gate capability probe: %v; no node-local DaemonSet or Kubernetes Node activation state was changed",
					displayVersion, err,
				),
			}
		}
		return unknownNodeLocalPoolCapability(fmt.Sprintf(
			"Kubernetes %s could not complete the node-local DaemonSet scheduling-gate dry run: %v",
			displayVersion, err,
		))
	}
	if !podSpecHasSchedulingGate(probe.Spec.Template.Spec, nodeLocalPoolCapabilityGateName) {
		return NodeLocalPoolPrerequisiteResult{
			Reason: garagev1beta1.ReasonNodeLocalPoolSchedulingGatesUnavailable,
			Message: fmt.Sprintf(
				"Kubernetes %s did not preserve the scheduling gate in the dry-run DaemonSet response; no node-local DaemonSet or Kubernetes Node activation state was changed",
				displayVersion,
			),
		}
	}

	schedulerResult := c.checkSchedulerSchedulingGate(ctx, cluster, displayVersion, now)
	if !schedulerResult.Supported {
		return schedulerResult
	}
	if schedulerResult.evidenceObservedAt.IsZero() {
		return unknownNodeLocalPoolCapability(
			"kube-scheduler returned successful scheduling-gate evidence without an observation timestamp",
		)
	}

	c.mu.Lock()
	for key, cached := range c.evidence {
		if !now.Before(cached.expiresAt) {
			delete(c.evidence, key)
		}
	}
	// The freshness window is anchored to kube-scheduler's actual condition,
	// not to the later instant at which this reconciliation consumed it. This
	// prevents manager restart/adoption latency from extending stale evidence.
	observedAt := schedulerResult.evidenceObservedAt
	expiresAt := observedAt.Add(c.evidenceTTL)
	evidence = nodeLocalPoolCapabilityEvidence{
		observedServerVersion: displayVersion,
		observedAt:            observedAt,
		expiresAt:             expiresAt,
	}
	c.evidence[evidenceKey] = evidence
	c.mu.Unlock()
	rememberNodeLocalPoolPrerequisiteSessionEvidence(ctx, evidenceKey, evidence)
	return supportedNodeLocalPoolCapability(namespace, evidence, false)
}

func unknownNodeLocalPoolCapability(detail string) NodeLocalPoolPrerequisiteResult {
	return NodeLocalPoolPrerequisiteResult{
		Reason: garagev1beta1.ReasonNodeLocalPoolSchedulingGateCapabilityUnknown,
		Message: fmt.Sprintf(
			"cannot prove that the Kubernetes API server and scheduler enforce the scheduling gates required by spec.storage.nodeLocalPools: %s; no node-local DaemonSet or Kubernetes Node activation state was changed",
			detail,
		),
	}
}

func pendingNodeLocalPoolSchedulerEvidence(detail string) NodeLocalPoolPrerequisiteResult {
	return NodeLocalPoolPrerequisiteResult{
		Reason:     garagev1beta1.ReasonNodeLocalPoolSchedulingGateProbePending,
		RetryAfter: nodeLocalPoolSchedulerProbeRetry,
		Message: fmt.Sprintf(
			"waiting for positive kube-scheduler PodScheduled=False reason=%s evidence: %s; no node-local DaemonSet or Kubernetes Node activation state was changed",
			corev1.PodReasonSchedulingGated, detail,
		),
	}
}

func unavailableNodeLocalPoolSchedulingGates(displayVersion, detail string) NodeLocalPoolPrerequisiteResult {
	return NodeLocalPoolPrerequisiteResult{
		Reason: garagev1beta1.ReasonNodeLocalPoolSchedulingGatesUnavailable,
		Message: fmt.Sprintf(
			"Kubernetes %s did not prove end-to-end Pod scheduling-gate enforcement: %s; no node-local DaemonSet or Kubernetes Node activation state was changed",
			displayVersion, detail,
		),
	}
}

func (c *nodeLocalPoolPrerequisiteChecker) checkSchedulerSchedulingGate(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
	displayVersion string,
	now time.Time,
) NodeLocalPoolPrerequisiteResult {
	key := client.ObjectKey{Namespace: cluster.Namespace, Name: nodeLocalPoolSchedulerProbeName(cluster)}
	probe := &corev1.Pod{}
	err := c.reader.Get(ctx, key, probe)
	if apierrors.IsNotFound(err) {
		probe = nodeLocalPoolSchedulingGatePodProbe(cluster)
		err = c.client.Create(ctx, probe)
		if apierrors.IsAlreadyExists(err) {
			probe = &corev1.Pod{}
			err = c.reader.Get(ctx, key, probe)
			if apierrors.IsNotFound(err) {
				return pendingNodeLocalPoolSchedulerEvidence(fmt.Sprintf(
					"probe Pod %s/%s exists in the API server but is not yet visible to the uncached reader",
					key.Namespace, key.Name,
				))
			}
		}
	}
	if err != nil {
		if apierrors.IsInvalid(err) || apierrors.IsBadRequest(err) || apierrors.IsNotFound(err) ||
			apierrors.IsMethodNotSupported(err) {
			return unavailableNodeLocalPoolSchedulingGates(
				displayVersion, fmt.Sprintf("the real gated scheduler probe Pod was rejected: %v", err),
			)
		}
		return unknownNodeLocalPoolCapability(fmt.Sprintf(
			"Kubernetes %s could not create or read the real gated scheduler probe Pod: %v",
			displayVersion, err,
		))
	}
	if !nodeLocalPoolSchedulerProbeBelongsToCluster(probe, cluster) {
		return unknownNodeLocalPoolCapability(fmt.Sprintf(
			"reserved scheduler probe Pod %s/%s exists but is not the exact probe for GarageCluster UID %s",
			probe.Namespace, probe.Name, cluster.UID,
		))
	}
	// Foreground garbage collection is allowed to delete controller-owned
	// dependants as soon as their owner starts deleting, even while our parent
	// finalizer still needs a scheduler proof before touching retained
	// activation state. Replace an inherited owned probe with the exact
	// deletion-safe ownerless form; normal finalization explicitly removes it.
	if !cluster.DeletionTimestamp.IsZero() && len(probe.OwnerReferences) != 0 {
		if deleteErr := c.deleteNodeLocalPoolSchedulerProbe(ctx, probe); deleteErr != nil {
			return unknownNodeLocalPoolCapability(fmt.Sprintf(
				"replacing controller-owned scheduler probe Pod %s/%s for deletion-safe proof: %v",
				probe.Namespace, probe.Name, deleteErr,
			))
		}
		return pendingNodeLocalPoolSchedulerEvidence(fmt.Sprintf(
			"controller-owned probe Pod %s/%s was removed before foreground deletion proof and will be recreated without a garbage-collection owner",
			probe.Namespace, probe.Name,
		))
	}
	if !podSpecHasSchedulingGate(probe.Spec, nodeLocalPoolCapabilityGateName) {
		if deleteErr := c.deleteNodeLocalPoolSchedulerProbe(ctx, probe); deleteErr != nil {
			return unknownNodeLocalPoolCapability(fmt.Sprintf(
				"Kubernetes %s removed the gate from the real scheduler probe and cleanup failed: %v",
				displayVersion, deleteErr,
			))
		}
		return unavailableNodeLocalPoolSchedulingGates(
			displayVersion, "the API server removed the gate from the real scheduler probe Pod",
		)
	}
	if !probe.DeletionTimestamp.IsZero() {
		return pendingNodeLocalPoolSchedulerEvidence(fmt.Sprintf(
			"previous probe Pod %s/%s is terminating", probe.Namespace, probe.Name,
		))
	}
	if probe.CreationTimestamp.IsZero() {
		if deleteErr := c.deleteNodeLocalPoolSchedulerProbe(ctx, probe); deleteErr != nil {
			return unknownNodeLocalPoolCapability(fmt.Sprintf(
				"scheduler probe Pod %s/%s has no API-server creation timestamp and cleanup failed: %v",
				probe.Namespace, probe.Name, deleteErr,
			))
		}
		return pendingNodeLocalPoolSchedulerEvidence(fmt.Sprintf(
			"probe Pod %s/%s had no API-server creation timestamp, was deleted, and will be recreated",
			probe.Namespace, probe.Name,
		))
	}
	if now.Sub(probe.CreationTimestamp.Time) >= nodeLocalPoolSchedulerProbeTimeout {
		if deleteErr := c.deleteNodeLocalPoolSchedulerProbe(ctx, probe); deleteErr != nil {
			return unknownNodeLocalPoolCapability(fmt.Sprintf(
				"stale scheduler probe Pod %s/%s exceeded %s and cleanup failed: %v",
				probe.Namespace, probe.Name, nodeLocalPoolSchedulerProbeTimeout, deleteErr,
			))
		}
		return pendingNodeLocalPoolSchedulerEvidence(fmt.Sprintf(
			"stale probe Pod %s/%s exceeded %s, was deleted, and must be reproved",
			probe.Namespace, probe.Name, nodeLocalPoolSchedulerProbeTimeout,
		))
	}
	if probe.Spec.NodeName != "" {
		if deleteErr := c.deleteNodeLocalPoolSchedulerProbe(ctx, probe); deleteErr != nil {
			return unknownNodeLocalPoolCapability(fmt.Sprintf(
				"kube-scheduler assigned gated probe Pod %s/%s to Node %s and cleanup failed: %v",
				probe.Namespace, probe.Name, probe.Spec.NodeName, deleteErr,
			))
		}
		return unavailableNodeLocalPoolSchedulingGates(displayVersion, fmt.Sprintf(
			"kube-scheduler assigned the still-gated probe Pod to Node %s", probe.Spec.NodeName,
		))
	}
	for i := range probe.Status.Conditions {
		condition := &probe.Status.Conditions[i]
		if condition.Type != corev1.PodScheduled {
			continue
		}
		if condition.Status == corev1.ConditionFalse && condition.Reason == corev1.PodReasonSchedulingGated {
			if condition.LastTransitionTime.IsZero() ||
				condition.LastTransitionTime.Time.Before(probe.CreationTimestamp.Time) ||
				now.Sub(condition.LastTransitionTime.Time) >= nodeLocalPoolSchedulerProbeTimeout {
				if deleteErr := c.deleteNodeLocalPoolSchedulerProbe(ctx, probe); deleteErr != nil {
					return unknownNodeLocalPoolCapability(fmt.Sprintf(
						"probe Pod %s/%s has stale or unbounded SchedulingGated evidence and cleanup failed: %v",
						probe.Namespace, probe.Name, deleteErr,
					))
				}
				return pendingNodeLocalPoolSchedulerEvidence(fmt.Sprintf(
					"probe Pod %s/%s had stale or unbounded SchedulingGated evidence, was deleted, and must be reproved",
					probe.Namespace, probe.Name,
				))
			}
			if deleteErr := c.deleteNodeLocalPoolSchedulerProbe(ctx, probe); deleteErr != nil {
				return unknownNodeLocalPoolCapability(fmt.Sprintf(
					"kube-scheduler proved SchedulingGated for probe Pod %s/%s but cleanup failed: %v",
					probe.Namespace, probe.Name, deleteErr,
				))
			}
			return NodeLocalPoolPrerequisiteResult{
				Supported:          true,
				evidenceObservedAt: condition.LastTransitionTime.Time,
			}
		}
		if deleteErr := c.deleteNodeLocalPoolSchedulerProbe(ctx, probe); deleteErr != nil {
			return unknownNodeLocalPoolCapability(fmt.Sprintf(
				"kube-scheduler reported PodScheduled=%s reason=%q for the gated probe and cleanup failed: %v",
				condition.Status, condition.Reason, deleteErr,
			))
		}
		return unavailableNodeLocalPoolSchedulingGates(displayVersion, fmt.Sprintf(
			"kube-scheduler evaluated the still-gated probe as PodScheduled=%s reason=%q instead of PodScheduled=False reason=%s",
			condition.Status, condition.Reason, corev1.PodReasonSchedulingGated,
		))
	}
	return pendingNodeLocalPoolSchedulerEvidence(fmt.Sprintf(
		"probe Pod %s/%s has not yet received a PodScheduled condition",
		probe.Namespace, probe.Name,
	))
}

func (c *nodeLocalPoolPrerequisiteChecker) deleteNodeLocalPoolSchedulerProbe(
	ctx context.Context,
	probe *corev1.Pod,
) error {
	if err := c.client.Delete(ctx, probe); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

func (r *GarageClusterReconciler) deleteRetainedNodeLocalPoolSchedulerProbe(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) error {
	if cluster == nil || cluster.Namespace == "" || cluster.UID == "" {
		return nil
	}
	probe := &corev1.Pod{}
	key := client.ObjectKey{Namespace: cluster.Namespace, Name: nodeLocalPoolSchedulerProbeName(cluster)}
	if err := r.nodeLocalPoolReader().Get(ctx, key, probe); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("reading retained node-local scheduler probe: %w", err)
	}
	if !nodeLocalPoolSchedulerProbeBelongsToCluster(probe, cluster) {
		return nil
	}
	if err := r.Delete(ctx, probe); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("deleting retained node-local scheduler probe: %w", err)
	}
	return nil
}

func parseKubernetesServerVersion(info *version.Info) (int, int, string, error) {
	if info == nil {
		return 0, 0, "", fmt.Errorf("kubernetes discovery returned no server version")
	}
	displayVersion := strings.TrimSpace(info.GitVersion)
	if displayVersion == "" {
		displayVersion = strings.TrimSpace(info.Major) + "." + strings.TrimSpace(info.Minor)
	}
	major, err := leadingVersionNumber(info.Major)
	if err != nil {
		return 0, 0, "", fmt.Errorf("kubernetes discovery returned invalid major version %q", info.Major)
	}
	minor, err := leadingVersionNumber(info.Minor)
	if err != nil {
		return 0, 0, "", fmt.Errorf("kubernetes discovery returned invalid minor version %q", info.Minor)
	}
	return major, minor, displayVersion, nil
}

func leadingVersionNumber(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	end := 0
	for end < len(raw) && raw[end] >= '0' && raw[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, fmt.Errorf("version component has no leading number")
	}
	return strconv.Atoi(raw[:end])
}

func nodeLocalPoolSchedulingGateDaemonSetProbe(namespace string) *appsv1.DaemonSet {
	labels := map[string]string{
		labelAppName:                      nodeLocalPoolCapabilityProbeApp,
		labelAppManagedBy:                 operatorName,
		nodeLocalPoolCapabilityProbeLabel: "api-dry-run",
	}
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "garage-node-local-capability-",
			Namespace:    namespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec:       nodeLocalPoolCapabilityProbePodSpec("api-dry-run", corev1.RestartPolicyAlways),
			},
		},
	}
}

func nodeLocalPoolSchedulingGatePodProbe(cluster *garagev1beta2.GarageCluster) *corev1.Pod {
	name := nodeLocalPoolSchedulerProbeName(cluster)
	suffix := strings.TrimPrefix(name, "garage-node-local-gate-probe-")
	probe := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: cluster.Namespace,
			Labels: map[string]string{
				labelAppName:                      nodeLocalPoolCapabilityProbeApp,
				labelAppManagedBy:                 operatorName,
				nodeLocalPoolCapabilityProbeLabel: "scheduler",
			},
			Annotations: map[string]string{nodeLocalPoolCapabilityProbeUID: string(cluster.UID)},
		},
		Spec: nodeLocalPoolCapabilityProbePodSpec("probe-"+suffix, corev1.RestartPolicyNever),
	}
	if cluster.DeletionTimestamp.IsZero() {
		probe.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(
			cluster, garagev1beta2.GroupVersion.WithKind(kindGarageCluster),
		)}
	}
	return probe
}

func nodeLocalPoolCapabilityProbePodSpec(
	nodeSelectorValue string,
	restartPolicy corev1.RestartPolicy,
) corev1.PodSpec {
	return corev1.PodSpec{
		RestartPolicy:                restartPolicy,
		AutomountServiceAccountToken: ptr.To(false),
		SchedulingGates:              []corev1.PodSchedulingGate{{Name: nodeLocalPoolCapabilityGateName}},
		// If a scheduler ignores the gate it can only report Unschedulable: no
		// real Node should carry this per-GarageCluster private selector value.
		NodeSelector: map[string]string{nodeLocalPoolCapabilityProbeLabel: nodeSelectorValue},
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot: ptr.To(true),
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
		},
		Containers: []corev1.Container{{
			Name:    "probe",
			Image:   "registry.k8s.io/pause:3.10",
			Command: []string{"/pause"},
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: ptr.To(false),
				ReadOnlyRootFilesystem:   ptr.To(true),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{capabilityAll},
				},
			},
		}},
	}
}

func nodeLocalPoolSchedulerProbeName(cluster *garagev1beta2.GarageCluster) string {
	if cluster == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(string(cluster.UID)))
	return fmt.Sprintf("garage-node-local-gate-probe-%x", sum[:6])
}

func nodeLocalPoolSchedulerProbeBelongsToCluster(
	probe *corev1.Pod,
	cluster *garagev1beta2.GarageCluster,
) bool {
	if probe == nil || cluster == nil || probe.Namespace != cluster.Namespace ||
		probe.Name != nodeLocalPoolSchedulerProbeName(cluster) ||
		probe.Labels[labelAppName] != nodeLocalPoolCapabilityProbeApp ||
		probe.Labels[labelAppManagedBy] != operatorName ||
		probe.Labels[nodeLocalPoolCapabilityProbeLabel] != "scheduler" ||
		probe.Annotations[nodeLocalPoolCapabilityProbeUID] != string(cluster.UID) ||
		probe.Spec.RestartPolicy != corev1.RestartPolicyNever {
		return false
	}
	if cluster.DeletionTimestamp.IsZero() {
		if len(probe.OwnerReferences) != 1 || !metav1.IsControlledBy(probe, cluster) {
			return false
		}
	} else if len(probe.OwnerReferences) != 0 &&
		(len(probe.OwnerReferences) != 1 || !metav1.IsControlledBy(probe, cluster)) {
		return false
	}
	expectedSelector := nodeLocalPoolSchedulingGatePodProbe(cluster).Spec.NodeSelector
	return len(probe.Spec.NodeSelector) == 1 &&
		probe.Spec.NodeSelector[nodeLocalPoolCapabilityProbeLabel] == expectedSelector[nodeLocalPoolCapabilityProbeLabel]
}

func podSpecHasSchedulingGate(spec corev1.PodSpec, expected string) bool {
	for _, gate := range spec.SchedulingGates {
		if gate.Name == expected {
			return true
		}
	}
	return false
}

func (r *GarageClusterReconciler) requireNodeLocalPoolPrerequisites(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) NodeLocalPoolPrerequisiteResult {
	if r.NodeLocalPoolPrerequisites == nil {
		return unknownNodeLocalPoolCapability("controller capability checker is not configured")
	}
	return r.NodeLocalPoolPrerequisites.Check(ctx, cluster)
}

func (r *GarageClusterReconciler) nodeLocalPoolPrerequisitesRequired(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (bool, error) {
	if cluster == nil {
		return false, nil
	}
	deleting := !cluster.DeletionTimestamp.IsZero()
	if (cluster.HasNodeLocalPools() && !deleting) ||
		(cluster.Status.StorageRollout != nil && cluster.Status.StorageRollout.NodeLocalPoolName != "") {
		return true, nil
	}
	// A cluster that never used the feature must remain compatible with
	// Kubernetes 1.25 and must not invoke discovery or the dry-run probe. During
	// deletion, however, desired spec is no longer proof that activation ever
	// happened, so inspect retained artifacts even if no condition was persisted.
	if !deleting && findNodeLocalPoolsReadyCondition(cluster) == nil {
		return false, nil
	}

	daemonSets := &appsv1.DaemonSetList{}
	if err := r.nodeLocalPoolReader().List(ctx, daemonSets,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name, labelTier: tierStorage}),
	); err != nil {
		return false, fmt.Errorf("listing retained node-local DaemonSets before prerequisite check: %w", err)
	}
	for i := range daemonSets.Items {
		daemonSet := &daemonSets.Items[i]
		if daemonSet.Labels[labelNodeLocalPool] != "" && metav1.IsControlledBy(daemonSet, cluster) {
			return true, nil
		}
	}

	garageNodes := &garagev1beta1.GarageNodeList{}
	if err := r.nodeLocalPoolReader().List(ctx, garageNodes,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(map[string]string{labelCluster: cluster.Name}),
	); err != nil {
		return false, fmt.Errorf("listing retained node-local GarageNodes before prerequisite check: %w", err)
	}
	for i := range garageNodes.Items {
		node := &garageNodes.Items[i]
		if node.Labels[labelNodeLocalPool] != "" &&
			node.Spec.ClusterRef.Name == cluster.Name && node.Spec.NodeLocalPoolName != "" {
			return true, nil
		}
	}

	// A crash can leave only the activation/claim rows after workload and child
	// cleanup. Those Node fields are still part of the safety protocol and may
	// only be mutated after capability evidence is available.
	if r.ClusterScoped {
		nodes := &corev1.NodeList{}
		if err := r.nodeLocalPoolReader().List(ctx, nodes); err != nil {
			return false, fmt.Errorf("listing Kubernetes Nodes for retained node-local activation state: %w", err)
		}
		activationPrefix := nodeLocalPoolActivationClusterPrefix(cluster)
		retainedAnnotationPrefix := nodeLocalPoolRetainedAnnotationClusterPrefix(cluster)
		for i := range nodes.Items {
			for key := range nodes.Items[i].Labels {
				if strings.HasPrefix(key, activationPrefix) {
					return true, nil
				}
			}
			for key := range nodes.Items[i].Annotations {
				if strings.HasPrefix(key, retainedAnnotationPrefix) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func findNodeLocalPoolsReadyCondition(cluster *garagev1beta2.GarageCluster) *metav1.Condition {
	if cluster == nil {
		return nil
	}
	for i := range cluster.Status.Conditions {
		if cluster.Status.Conditions[i].Type == garagev1beta1.ConditionNodeLocalPoolsReady {
			return &cluster.Status.Conditions[i]
		}
	}
	return nil
}

func (r *GarageClusterReconciler) blockForNodeLocalPoolPrerequisites(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) (bool, time.Duration, error) {
	required, err := r.nodeLocalPoolPrerequisitesRequired(ctx, cluster)
	if err != nil {
		return false, 0, err
	}
	if !required {
		// A manager can stop after creating the real scheduler probe but before
		// persisting the pending condition. Always clean the deterministic Pod
		// when the feature no longer has retained state; the owner reference is
		// the final backstop if the GarageCluster is force-deleted.
		if err := r.deleteRetainedNodeLocalPoolSchedulerProbe(ctx, cluster); err != nil {
			return false, 0, err
		}
		return false, 0, nil
	}
	result := r.requireNodeLocalPoolPrerequisites(ctx, cluster)
	if result.Supported {
		return false, 0, nil
	}
	if err := r.setNodeLocalPoolsCondition(
		ctx, cluster, metav1.ConditionFalse, result.Reason, result.Message,
	); err != nil {
		return false, 0, fmt.Errorf("recording node-local prerequisite failure: %w", err)
	}
	return true, result.RetryAfter, nil
}

func (r *GarageClusterReconciler) assertNodeLocalPoolPrerequisites(
	ctx context.Context,
	cluster *garagev1beta2.GarageCluster,
) error {
	result := r.requireNodeLocalPoolPrerequisites(ctx, cluster)
	if result.Supported {
		return nil
	}
	return fmt.Errorf("node-local pool prerequisite %s: %s", result.Reason, result.Message)
}
