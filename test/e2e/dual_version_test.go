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
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rajsinghtech/garage-operator/test/utils"
)

// stripKubectlWarnings drops any line beginning with "Warning:" (kubectl emits
// deprecation warnings on stderr, but utils.Run combines stderr+stdout). Used
// when reading via the deprecated v1beta1 endpoint.
func stripKubectlWarnings(s string) string {
	var keep []string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Warning:") {
			continue
		}
		keep = append(keep, line)
	}
	return strings.TrimSpace(strings.Join(keep, "\n"))
}

// These specs cover the dual API-version migration story:
//
//  1. v1beta1 storage cluster works as-is (backward compat)
//  2. v1beta1 gateway+connectTo works (backward compat for edge gateways)
//  3. v1beta2 unified cluster (storage + gateway in one CR)
//  4. v1beta2 edge gateway with connectTo.adminApiEndpoint
//  5. Conversion round-trip via kubectl
//  6. Scale subresource preserves the version-specific storage/gateway contract
//  7. v1beta2 node-local pools survive a live v1beta1 read/write, while the
//     conversion transport remains protected from v1beta1 clients
//  8. v1beta1 dual-CR setup keeps working without migration
//  9. Migration from two-CR (v1beta1) to single-CR (v1beta2) cleans layout
//  10. Tombstone cleanup on gateway scale up/down
//  11. Persistent gateway identity survives pod replacement
//
// The suite assumes the operator is already deployed by the main e2e suite's
// BeforeAll. We share its namespace and admin token where convenient and create
// scoped CRs per scenario.

var _ = Describe("Dual API Version", Ordered, Label("dual-version"), func() {
	const (
		testNS                 = "garage-dualver"
		adminTokenSecret       = "garage-admin-token-dv"
		adminTokenValue        = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		v1Storage              = "v1-storage"
		v1Gateway              = "v1-gateway"
		v2Unified              = "v2-unified"
		v2EdgeGateway          = "v2-edge-gateway"
		v1RoundtripCluster     = "v1-roundtrip"
		v2NodeLocalConversion  = "v2-node-local-conversion"
		v1MigrateStorage       = "migrate-storage"
		v1MigrateGateway       = "migrate-gateway"
		v2ScaleCluster         = "v2-scale"
		v2RotationCluster      = "v2-rotation"
		v1beta2LossyAnnotation = "garage.rajsingh.info/v1beta2-only"
		v1beta2NodeLocalMarker = "node-local-pools-present"
		v1beta2NodeLocalData   = "garage.rajsingh.info/v1beta2-node-local-pools"
	)
	type gatewayTopologySnapshot struct {
		Metadata struct {
			Generation int64 `json:"generation"`
		} `json:"metadata"`
		Status struct {
			ObservedGeneration   int64 `json:"observedGeneration"`
			GatewayReplicas      int   `json:"gatewayReplicas"`
			GatewayReadyReplicas int   `json:"gatewayReadyReplicas"`
			StorageDrain         *struct {
				TransactionID string `json:"transactionId"`
			} `json:"storageDrain"`
		} `json:"status"`
	}
	type gatewayNodeList struct {
		Items []struct {
			Metadata struct {
				Name              string  `json:"name"`
				DeletionTimestamp *string `json:"deletionTimestamp"`
			} `json:"metadata"`
		} `json:"items"`
	}
	gatewayRoleIDs := func(layout garageLayoutSnapshot) []string {
		ids := make([]string, 0)
		for _, role := range layout.Roles {
			gatewayTag := false
			for _, tag := range role.Tags {
				if tag == "tier:gateway" {
					gatewayTag = true
					break
				}
			}
			if gatewayTag && role.Capacity == nil && role.ID != "" {
				ids = append(ids, role.ID)
			}
		}
		return ids
	}
	applyManifest := func(manifest, description string) {
		GinkgoHelper()
		// The webhook route can briefly disappear during a controller rollout or
		// EndpointSlice update. Applying an idempotent manifest is safe to retry;
		// keep the retry bounded so a real schema/admission error is still reported
		// by this spec.
		Eventually(func(g Gomega) {
			apply := exec.Command("kubectl", "apply", "-f", "-")
			apply.Stdin = strings.NewReader(manifest)
			out, err := utils.Run(apply)
			g.Expect(err).NotTo(HaveOccurred(), "%s: %s", description, out)
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	}

	gatewayTopologyConverged := func(g Gomega, replicas int) {
		out, err := utils.Run(exec.Command("kubectl", "get", "garageclusters.v1beta2.garage.rajsingh.info", v2ScaleCluster, "-n", testNS, "-o", "json"))
		g.Expect(err).NotTo(HaveOccurred())
		var snapshot gatewayTopologySnapshot
		g.Expect(json.Unmarshal([]byte(out), &snapshot)).To(Succeed())
		g.Expect(snapshot.Status.ObservedGeneration).To(Equal(snapshot.Metadata.Generation),
			"cluster status has not observed the current scale generation")
		g.Expect(snapshot.Status.GatewayReplicas).To(Equal(replicas))
		g.Expect(snapshot.Status.GatewayReadyReplicas).To(Equal(replicas))
		g.Expect(snapshot.Status.StorageDrain).To(BeNil(),
			"the prior exact gateway drain actor must complete before another topology mutation")

		out, err = utils.Run(exec.Command("kubectl", "get", "garagenodes.garage.rajsingh.info", "-n", testNS,
			"-l", "garage.rajsingh.info/cluster="+v2ScaleCluster+",garage.rajsingh.info/tier=gateway", "-o", "json"))
		g.Expect(err).NotTo(HaveOccurred())
		var nodes gatewayNodeList
		g.Expect(json.Unmarshal([]byte(out), &nodes)).To(Succeed())
		g.Expect(nodes.Items).To(HaveLen(replicas),
			"all serialized gateway retirements or admissions must finish before reversing direction")
		for _, node := range nodes.Items {
			g.Expect(node.Metadata.DeletionTimestamp).To(BeNil(),
				"gateway GarageNode %s is still retiring", node.Metadata.Name)
		}

		layout, history := readGarageLayoutSnapshot(
			g, testNS, "dual-version-gateway-topology", v2ScaleCluster, adminTokenValue,
		)
		g.Expect(layout.StagedRoleChanges).To(BeEmpty(),
			"Garage's live global staging area must be empty before reversing scale direction")
		g.Expect(history.CurrentVersion).To(BeNumerically(">", 0))
		g.Expect(history.MinAck).To(BeNumerically(">=", history.CurrentVersion),
			"every Garage node must acknowledge the current layout before the next topology mutation")

		currentEntries := 0
		for _, version := range history.Versions {
			g.Expect(version.Status).NotTo(Equal("Draining"),
				"another topology mutation must not begin while Garage still drains layout version %d", version.Version)
			if version.Status == "Current" && version.Version == history.CurrentVersion {
				currentEntries++
				g.Expect(version.GatewayNodes).To(Equal(replicas),
					"Garage's live current layout does not contain the requested gateway membership")
			}
		}
		g.Expect(currentEntries).To(Equal(1), "expected one live current layout-history entry")
	}

	BeforeAll(func() {
		// Ginkgo does not guarantee Describe ordering across files, so this
		// spec cannot assume the main Manager Describe's BeforeAll has run.
		// Install CRDs + operator here directly; both make targets are
		// idempotent (server-side apply) and skipped no-ops once present.
		By("installing CRDs (dual-version suite)")
		cmd := exec.Command("make", "install")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("waiting for Garage CRDs to be Established")
		Expect(utils.WaitCRDsEstablished()).To(Succeed())

		By("deploying the controller-manager (dual-version suite)")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("waiting for a Ready controller-manager Pod")
		Eventually(func(g Gomega) {
			_, err := controllerManagerPodReady(namespace)
			g.Expect(err).NotTo(HaveOccurred(), "controller-manager is not Ready")
		}, 3*time.Minute, 5*time.Second).Should(Succeed())
		Expect(waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())

		By("creating dual-version test namespace")
		Expect(createE2ETestNamespace(testNS)).To(Succeed())

		By("labeling namespace with restricted PSA")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNS,
			"pod-security.kubernetes.io/enforce=restricted")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label dual-version namespace: %s", output)

		By("creating admin token secret")
		yaml := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque
stringData:
  admin-token: "%s"
`, adminTokenSecret, testNS, adminTokenValue)
		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(yaml)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		// This block creates many connected storage/gateway CRs. Deleting all
		// parents concurrently lets a gateway finalizer lose the storage CR it
		// references, while a normal storage finalizer can retain its child
		// GarageNodes. Use the bounded teardown that disables admission, stops
		// reconciliation, and clears finalizers before deleting the namespace.
		cleanupAuto190(testNS, nil)
	})

	// Scenario 1: v1beta1 storage cluster works as-is.
	It("accepts an existing-style v1beta1 storage CR and reconciles a StatefulSet+PVCs", func() {
		yaml := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  replication:
    factor: 1
  storage:
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
  admin:
    adminTokenSecretRef:
      name: %s
      key: admin-token
  security:
    allowInsecureSecretPermissions: true
`, v1Storage, testNS, adminTokenSecret)

		By("applying the v1beta1 storage manifest after the webhook route is ready")
		applyManifest(yaml, "apply v1beta1 storage")

		By("expecting the operator to reconcile a per-node StatefulSet (Auto mode → <cluster>-storage-0)")
		Eventually(func(g Gomega) {
			get := exec.Command("kubectl", "get", "statefulset", v1Storage+"-storage-0", "-n", testNS, "-o", "jsonpath={.spec.replicas}")
			o, err := utils.Run(get)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(o).To(Equal("1"))
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("expecting PVCs to be provisioned for metadata+data on the per-node STS")
		Eventually(func(g Gomega) {
			get := exec.Command("kubectl", "get", "pvc", "-n", testNS,
				"-l", "garage.rajsingh.info/node="+v1Storage+"-storage-0", "-o", "jsonpath={.items[*].metadata.name}")
			o, err := utils.Run(get)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(o).NotTo(BeEmpty(), "expected at least one PVC for v1beta1 storage cluster's per-node STS")
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("expecting the cluster to expose its storage replicas under status.storageReplicas (v1beta2 view)")
		Eventually(func(g Gomega) {
			// Reading via v1beta2 endpoint should show new fields populated.
			get := exec.Command("kubectl", "get", "garageclusters.v1beta2.garage.rajsingh.info", v1Storage, "-n", testNS,
				"-o", "jsonpath={.status.storageReplicas}")
			o, err := utils.Run(get)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(o).To(Or(Equal("1"), Equal("")), "got %q", o)
		}, 3*time.Minute, 5*time.Second).Should(Succeed())
	})

	// Scenario 2: v1beta1 gateway+connectTo works.
	It("accepts an existing-style v1beta1 gateway CR with connectTo (edge gateway)", func() {
		// The namespace enforces pod-security restricted, so this CR needs an
		// explicit compliant pod template. Without it the edge gateway's
		// StatefulSet is created but every pod is rejected at admission, and the
		// later Scale scenario — which asserts status.replicas, not just object
		// existence — can never observe a running replica.
		yaml := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
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
      name: %s
      key: admin-token
  security:
    allowInsecureSecretPermissions: true
`, v1Gateway, testNS, v1Storage, adminTokenSecret)

		applyManifest(yaml, "apply v1beta1 gateway")

		By("expecting a StatefulSet (gateway tier) — controller converts v1beta1 gateway=true to v1beta2 gateway tier")
		Eventually(func(g Gomega) {
			get := exec.Command("kubectl", "get", "statefulset", v1Gateway+"-gateway", "-n", testNS,
				"-o", "jsonpath={.spec.replicas}")
			o, err := utils.Run(get)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(o).To(Equal("1"))
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("expecting a metadata PVC per gateway replica (persistent node identity)")
		Eventually(func(g Gomega) {
			get := exec.Command("kubectl", "get", "pvc", "-n", testNS,
				"-l", "app.kubernetes.io/instance="+v1Gateway, "-o", "jsonpath={.items[*].metadata.name}")
			o, err := utils.Run(get)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(o).NotTo(BeEmpty(), "gateway pods must have metadata PVCs")
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	// Scenario 3: v1beta2 unified cluster (storage + gateway in one CR).
	It("reconciles a v1beta2 unified cluster (storage + gateway tiers in one CR)", func() {
		// Storage must become layout-ready before the gateway topology is
		// materialized. Give both tiers restricted-compliant pod templates so
		// this scenario exercises that complete transition instead of merely
		// observing StatefulSet objects whose pods cannot be admitted.
		yaml := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  replication: {factor: 1}
  storage:
    replicas: 1
    metadata: {size: 1Gi}
    data:     {size: 1Gi}
    resources: {limits: {memory: 256Mi}, requests: {memory: 128Mi}}
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
    resources: {limits: {memory: 256Mi}, requests: {memory: 64Mi}}
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
      name: %s
      key: admin-token
  security:
    allowInsecureSecretPermissions: true
`, v2Unified, testNS, adminTokenSecret)

		applyManifest(yaml, "apply v1beta2 unified")

		By("expecting per-node storage AND per-node gateway StatefulSets")
		// Post-#190 storage is per-GarageNode (<cluster>-storage-N). Post-#209 the
		// gateway tier of a UNIFIED cluster is ALSO per-GarageNode
		// (<cluster>-gateway-N) — not a single cluster-level <cluster>-gateway STS.
		Eventually(func(g Gomega) {
			get := exec.Command("kubectl", "get", "statefulset", v2Unified+"-storage-0", "-n", testNS)
			_, err := utils.Run(get)
			g.Expect(err).NotTo(HaveOccurred())
		}, 3*time.Minute, 5*time.Second).Should(Succeed())
		Eventually(func(g Gomega) {
			get := exec.Command("kubectl", "get", "statefulset", v2Unified+"-gateway-0", "-n", testNS)
			_, err := utils.Run(get)
			g.Expect(err).NotTo(HaveOccurred())
		}, 3*time.Minute, 5*time.Second).Should(Succeed())
		By("expecting NO legacy cluster-level gateway StatefulSet")
		Consistently(func(g Gomega) {
			get := exec.Command("kubectl", "get", "statefulset", v2Unified+"-gateway", "-n", testNS, "--ignore-not-found", "-o", "jsonpath={.metadata.name}")
			out, err := utils.Run(get)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(BeEmpty())
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	// Scenario 4: v1beta2 edge gateway with connectTo.adminApiEndpoint.
	// We can't construct a fully external admin endpoint in a kind cluster easily,
	// so we exercise the same code path by pointing connectTo.clusterRef at an
	// in-cluster storage CR (functionally edge gateway -- different CR; controller
	// uses local admin client).
	It("reconciles a v1beta2 edge gateway CR (gateway-only + connectTo)", func() {
		yaml := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  gateway:
    replicas: 1
  connectTo:
    clusterRef:
      name: %s
  admin:
    adminTokenSecretRef:
      name: %s
      key: admin-token
  security:
    allowInsecureSecretPermissions: true
`, v2EdgeGateway, testNS, v1Storage, adminTokenSecret)

		applyManifest(yaml, "apply v1beta2 edge gateway")

		By("expecting a StatefulSet for the gateway tier")
		Eventually(func(g Gomega) {
			get := exec.Command("kubectl", "get", "statefulset", v2EdgeGateway+"-gateway", "-n", testNS)
			_, err := utils.Run(get)
			g.Expect(err).NotTo(HaveOccurred())
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("expecting no storage-tier StatefulSet (no storage tier on this CR)")
		Consistently(func(g Gomega) {
			get := exec.Command("kubectl", "get", "statefulset", v2EdgeGateway, "-n", testNS)
			_, err := utils.Run(get)
			g.Expect(err).To(HaveOccurred())
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	// Scenario 5: Conversion round-trip via kubectl.
	It("converts a v1beta1 storage CR to v1beta2 via the conversion webhook on read", func() {
		yaml := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  replication: {factor: 1}
  storage:
    metadata: {size: 1Gi}
    data:     {size: 1Gi}
  nodeSelector:
    role: storage
  admin:
    adminTokenSecretRef:
      name: %s
      key: admin-token
  security:
    allowInsecureSecretPermissions: true
`, v1RoundtripCluster, testNS, adminTokenSecret)

		applyManifest(yaml, "apply v1beta1 round-trip fixture")

		By("reading via v1beta2 endpoint: expect tier-shaped JSON")
		var out string
		Eventually(func(g Gomega) {
			get := exec.Command("kubectl", "get", "garageclusters.v1beta2.garage.rajsingh.info", v1RoundtripCluster, "-n", testNS,
				"-o", "jsonpath={.spec.storage.replicas}")
			var err error
			out, err = utils.Run(get)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal("1"), "v1beta2 view should show storage.replicas=1, got %q", out)
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("reading podTemplate.nodeSelector via v1beta2")
		Eventually(func(g Gomega) {
			get := exec.Command("kubectl", "get", "garageclusters.v1beta2.garage.rajsingh.info", v1RoundtripCluster, "-n", testNS,
				"-o", "jsonpath={.spec.storage.nodeSelector.role}")
			var err error
			out, err = utils.Run(get)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal("storage"), "v1beta2 view should lift nodeSelector into storage podTemplate, got %q", out)
		}, 2*time.Minute, 5*time.Second).Should(Succeed())

		By("reading via v1beta1 endpoint: expect old-shape JSON")
		// Use the fully-qualified plural ("garageclusters.v1beta1.<group>"). The shortname
		// form ("gc.v1beta1.<group>") triggers kubectl's REST mapper to resolve the storage
		// version instead of the requested one, so the conversion webhook is bypassed and the
		// raw v1beta2 object is returned (with no .spec.replicas).
		Eventually(func(g Gomega) {
			get := exec.Command("kubectl", "get", "garageclusters.v1beta1.garage.rajsingh.info", v1RoundtripCluster, "-n", testNS,
				"-o", "jsonpath={.spec.replicas}")
			var err error
			out, err = utils.Run(get)
			g.Expect(err).NotTo(HaveOccurred())
			out = stripKubectlWarnings(out)
			g.Expect(out).To(Equal("1"), "v1beta1 view should expose spec.replicas, got %q", out)
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	// Scenario 6: exercise the live Scale paths/selectors in both served API
	// versions. v1beta1 retains its legacy edge-gateway target; v1beta2 targets
	// only the Auto default storage group and rejects gateway-only writes.
	It("exposes version-correct Scale targets without counting hidden tiers", func() {
		defaultSelector := func(name string) string {
			return "garage.rajsingh.info/cluster=" + name +
				",garage.rajsingh.info/storage-group=default" +
				",garage.rajsingh.info/tier=storage"
		}
		gatewaySelector := func(name string) string {
			return "garage.rajsingh.info/cluster=" + name +
				",garage.rajsingh.info/tier=gateway"
		}

		By("proving v1beta1 storage Scale targets the default storage group")
		Eventually(func(g Gomega) {
			scale, err := readGarageClusterScale("v1beta1", testNS, v1Storage)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(scale.Spec.Replicas).To(Equal(int32(1)))
			g.Expect(scale.Status.Replicas).To(Equal(int32(1)))
			g.Expect(scale.Status.Selector).To(Equal(defaultSelector(v1Storage)))
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("proving v1beta1 edge Scale retains its gateway workload contract")
		Eventually(func(g Gomega) {
			scale, err := readGarageClusterScale("v1beta1", testNS, v1Gateway)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(scale.Spec.Replicas).To(Equal(int32(1)))
			g.Expect(scale.Status.Replicas).To(Equal(int32(1)))
			g.Expect(scale.Status.Selector).To(Equal(gatewaySelector(v1Gateway)))
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("proving unified Scale excludes the hidden gateway tier through both API views")
		Eventually(func(g Gomega) {
			for _, apiVersion := range []string{"v1beta1", "v1beta2"} {
				scale, err := readGarageClusterScale(apiVersion, testNS, v2Unified)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(scale.Spec.Replicas).To(Equal(int32(1)), "apiVersion %s", apiVersion)
				g.Expect(scale.Status.Replicas).To(Equal(int32(1)), "apiVersion %s", apiVersion)
				g.Expect(scale.Status.Selector).To(Equal(defaultSelector(v2Unified)),
					"apiVersion %s must not select the gateway Pod", apiVersion)
			}
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("proving a v1beta2 gateway-only Scale write fails closed")
		out, err := utils.Run(exec.Command(
			"kubectl", "scale", "garageclusters.v1beta2.garage.rajsingh.info", v2EdgeGateway,
			"-n", testNS, "--replicas=2",
		))
		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring("v1beta2 Scale is available only for the Auto default storage group"))
	})

	// Scenario 7: exercise the v1beta2-only node-local pool conversion transport
	// through the live API server. Suspension makes this an API/admission test:
	// no DaemonSet, scheduling gate, activation label, or HostPath claim is
	// allowed to obscure whether conversion itself is lossless and fail-closed.
	It("preserves node-local pools through a v1beta1 write and protects the conversion transport", Label("node-local-conversion"), func() {
		yaml := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  maintenance:
    suspended: true
  replication: {factor: 1}
  storage:
    replicas: 0
    nodeLocalPools:
      - name: local
        selector:
          matchLabels:
            garage.rajsingh.info/e2e-conversion-never: "true"
        capacity: 1Gi
        metadata:
          hostPath: /var/lib/garage-e2e-conversion/meta
          hostPathType: Directory
        data:
          hostPath: /var/lib/garage-e2e-conversion/data
          hostPathType: Directory
  admin:
    adminTokenSecretRef: {name: %s, key: admin-token}
  security: {allowInsecureSecretPermissions: true}
`, v2NodeLocalConversion, testNS, adminTokenSecret)

		applyManifest(yaml, "apply suspended node-local conversion fixture")

		readV1beta1 := func() map[string]any {
			out, err := utils.Run(exec.Command(
				"kubectl", "get", "garageclusters.v1beta1.garage.rajsingh.info",
				v2NodeLocalConversion, "-n", testNS, "-o", "json",
			))
			Expect(err).NotTo(HaveOccurred(), "read node-local fixture through v1beta1: %s", out)
			var view map[string]any
			Expect(json.Unmarshal([]byte(stripKubectlWarnings(out)), &view)).To(Succeed())
			return view
		}
		objectMap := func(parent map[string]any, key string) map[string]any {
			value, ok := parent[key].(map[string]any)
			Expect(ok).To(BeTrue(), "expected %q to be an object in %#v", key, parent)
			return value
		}
		replaceV1beta1 := func(view map[string]any) (string, error) {
			body, err := json.Marshal(view)
			Expect(err).NotTo(HaveOccurred())
			replace := exec.Command("kubectl", "replace", "-f", "-")
			replace.Stdin = strings.NewReader(string(body))
			return utils.Run(replace)
		}
		// Each negative case below is a read-modify-replace against a live object
		// the operator is also writing (status, conditions). Losing that race
		// returns 409 Conflict from optimistic concurrency *before* admission
		// runs, so the rejection under test never happens. Retry on conflict with
		// a fresh read so these assertions exercise the webhook, not resourceVersion
		// timing.
		expectRejected := func(mutate func(map[string]any), want string) {
			GinkgoHelper()
			Eventually(func(g Gomega) {
				view := readV1beta1()
				mutate(view)
				out, err := replaceV1beta1(view)
				g.Expect(err).To(HaveOccurred(), "expected %q to be rejected, got: %s", want, out)
				g.Expect(out).NotTo(ContainSubstring("please apply your changes to the latest version"),
					"lost the optimistic-concurrency race; retrying with a fresh read")
				g.Expect(out).To(ContainSubstring(want))
			}, time.Minute, 2*time.Second).Should(Succeed())
		}

		By("checking the final node-local conversion key and marker in the v1beta1 view")
		view := readV1beta1()
		annotations := objectMap(objectMap(view, "metadata"), "annotations")
		payload, ok := annotations[v1beta2NodeLocalData].(string)
		Expect(ok).To(BeTrue())
		Expect(payload).NotTo(BeEmpty())
		marker, ok := annotations[v1beta2LossyAnnotation].(string)
		Expect(ok).To(BeTrue())
		Expect(marker).To(Equal(v1beta2NodeLocalMarker),
			"a pool-only projection must emit only the final node-local marker")
		Expect(annotations).NotTo(HaveKey("garage.rajsingh.info/v1beta2-storage-pools"),
			"an unreleased alias must never become an active conversion input")
		Expect(marker).NotTo(ContainSubstring("storage-pools"))
		var preservedPools []any
		Expect(json.Unmarshal([]byte(payload), &preservedPools)).To(Succeed())
		Expect(preservedPools).To(HaveLen(1))
		if len(preservedPools) != 1 {
			return
		}
		preservedPool, ok := preservedPools[0].(map[string]any)
		Expect(ok).To(BeTrue())
		Expect(preservedPool).To(HaveKeyWithValue("name", "local"))

		By("editing a v1beta1-representable field and writing the complete v1beta1 view back")
		var out string
		var err error
		objectMap(view, "spec")["imagePullPolicy"] = "Always"
		out, err = replaceV1beta1(view)
		Expect(err).NotTo(HaveOccurred(), "replace node-local fixture through v1beta1: %s", out)

		By("confirming v1beta2-only pools survived and transport annotations did not leak into stored hub state")
		out, err = utils.Run(exec.Command(
			"kubectl", "get", "garageclusters.v1beta2.garage.rajsingh.info",
			v2NodeLocalConversion, "-n", testNS, "-o", "json",
		))
		Expect(err).NotTo(HaveOccurred())
		var hub map[string]any
		Expect(json.Unmarshal([]byte(out), &hub)).To(Succeed())
		hubMetadata := objectMap(hub, "metadata")
		hubAnnotations, _ := hubMetadata["annotations"].(map[string]any)
		Expect(hubAnnotations).NotTo(HaveKey(v1beta2NodeLocalData))
		if hubMarker, found := hubAnnotations[v1beta2LossyAnnotation]; found {
			Expect(fmt.Sprint(hubMarker)).NotTo(ContainSubstring(v1beta2NodeLocalMarker))
		}
		hubSpec := objectMap(hub, "spec")
		Expect(hubSpec).To(HaveKeyWithValue("imagePullPolicy", "Always"))
		hubStorage := objectMap(hubSpec, "storage")
		hubPools, ok := hubStorage["nodeLocalPools"].([]any)
		Expect(ok).To(BeTrue())
		Expect(hubPools).To(HaveLen(1))
		if len(hubPools) != 1 {
			return
		}
		Expect(hubPools).To(Equal(preservedPools),
			"the complete selector/capacity/HostPath profile must survive the v1beta1 write")
		hubPool, ok := hubPools[0].(map[string]any)
		Expect(ok).To(BeTrue())
		Expect(hubPool).To(HaveKeyWithValue("name", "local"))
		Expect(objectMap(hubPool, "metadata")).To(HaveKeyWithValue("hostPath", "/var/lib/garage-e2e-conversion/meta"))
		Expect(objectMap(hubPool, "data")).To(HaveKeyWithValue("hostPath", "/var/lib/garage-e2e-conversion/data"))

		By("proving a v1beta1 client cannot remove the reserved pool payload")
		expectRejected(func(v map[string]any) {
			delete(objectMap(objectMap(v, "metadata"), "annotations"), v1beta2NodeLocalData)
		}, "reserved conversion payload")

		By("proving a v1beta1 client cannot mutate the reserved pool payload")
		expectRejected(func(v map[string]any) {
			objectMap(objectMap(v, "metadata"), "annotations")[v1beta2NodeLocalData] = "[]"
		}, "reserved conversion payload")

		By("proving a v1beta1 client cannot remove the reserved node-local marker")
		expectRejected(func(v map[string]any) {
			delete(objectMap(objectMap(v, "metadata"), "annotations"), v1beta2LossyAnnotation)
		}, "must retain")

		By("proving a v1beta1 client cannot replace the node-local marker with another component")
		expectRejected(func(v map[string]any) {
			objectMap(objectMap(v, "metadata"), "annotations")[v1beta2LossyAnnotation] = "gateway-tier-present"
		}, "must retain")
	})

	// Scenario 8: keep both v1beta1 storage + v1beta1 gateway as separate CRs (legacy two-CR pattern).
	It("reconciles two existing v1beta1 CRs (storage + gateway) without forcing migration", func() {
		storageYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  replication: {factor: 1}
  storage:
    metadata: {size: 1Gi}
    data:     {size: 1Gi}
  admin:
    adminTokenSecretRef: {name: %s, key: admin-token}
  security: {allowInsecureSecretPermissions: true}
`, v1MigrateStorage, testNS, adminTokenSecret)

		applyManifest(storageYAML, "apply legacy storage fixture")

		gatewayYAML := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  gateway: true
  connectTo:
    clusterRef: {name: %s}
  admin:
    adminTokenSecretRef: {name: %s, key: admin-token}
  security: {allowInsecureSecretPermissions: true}
`, v1MigrateGateway, testNS, v1MigrateStorage, adminTokenSecret)

		applyManifest(gatewayYAML, "apply legacy gateway fixture")

		By("verifying both CRs reconcile to expected workloads")
		// Post-#190: storage tier reconciles to per-node STS named <cluster>-storage-N.
		Eventually(func(g Gomega) {
			_, err := utils.Run(exec.Command("kubectl", "get", "statefulset", v1MigrateStorage+"-storage-0", "-n", testNS))
			g.Expect(err).NotTo(HaveOccurred())
		}, 3*time.Minute, 5*time.Second).Should(Succeed())
		Eventually(func(g Gomega) {
			_, err := utils.Run(exec.Command("kubectl", "get", "statefulset", v1MigrateGateway+"-gateway", "-n", testNS))
			g.Expect(err).NotTo(HaveOccurred())
		}, 3*time.Minute, 5*time.Second).Should(Succeed())
	})

	// Scenario 9: migrate two-CR (v1beta1 storage + v1beta1 gateway) into one v1beta2 unified CR.
	It("supports migrating a two-CR setup to a single v1beta2 unified CR", func() {
		Skip("requires careful inter-test ordering and a clean layout; covered manually for now")

		By("deleting the v1beta1 gateway CR; the v1beta1 storage CR survives")
		_, err := utils.Run(exec.Command("kubectl", "delete", "garageclusters.v1beta1.garage.rajsingh.info", v1MigrateGateway,
			"-n", testNS, "--ignore-not-found", "--timeout=2m"))
		Expect(err).NotTo(HaveOccurred())

		By("updating the v1beta1 storage CR to v1beta2 unified form (kubectl apply with new apiVersion is rejected — must delete+recreate or apply via patch)")
		yaml := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  replication: {factor: 1}
  storage:
    replicas: 1
    metadata: {size: 1Gi}
    data:     {size: 1Gi}
  gateway:
    replicas: 1
  admin:
    adminTokenSecretRef: {name: %s, key: admin-token}
  security: {allowInsecureSecretPermissions: true}
`, v1MigrateStorage, testNS, adminTokenSecret)
		applyManifest(yaml, "apply migrated unified fixture")

		By("operator must clean up stale tier:gateway entries from the deleted v1beta1 gateway CR")
		Eventually(func(g Gomega) {
			out, err := utils.Run(exec.Command("kubectl", "get", "garageclusters.v1beta2.garage.rajsingh.info", v1MigrateStorage, "-n", testNS,
				"-o", "jsonpath={.status.pendingGatewayTombstones}"))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Or(Equal("[]"), Equal("")), "expected pendingGatewayTombstones empty after cleanup, got %q", out)
		}, 5*time.Minute, 10*time.Second).Should(Succeed())
	})

	// Scenario 10: tombstone cleanup on gateway scale up/down.
	It("cleans up stale layout entries when the gateway tier scales down, and adds new ones on scale up", func() {
		// securityContext blocks are required because the namespace is labeled
		// pod-security.kubernetes.io/enforce=restricted. Earlier v1beta2 specs
		// only assert object existence, so a missing securityContext never
		// surfaced as a failure — but this spec waits on actual pod readiness.
		yaml := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  replication: {factor: 1}
  storage:
    replicas: 1
    metadata: {size: 1Gi}
    data:     {size: 1Gi}
    resources: {limits: {memory: 256Mi}, requests: {memory: 128Mi}}
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
    replicas: 3
    resources: {limits: {memory: 256Mi}, requests: {memory: 64Mi}}
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
  layoutManagement:
    autoApply: true
  admin:
    adminTokenSecretRef: {name: %s, key: admin-token}
  security: {allowInsecureSecretPermissions: true}
`, v2ScaleCluster, testNS, adminTokenSecret)
		applyManifest(yaml, "apply gateway topology fixture")
		var err error

		// Scenarios 1-8 leave their clusters running in this namespace (they
		// only assert initial reconcile, not full readiness, and there is no
		// per-spec cleanup). By the time this spec runs there are ~6 garage
		// clusters scheduling on a single-node kind cluster, so initial pod
		// startup for v2-scale plus the 3 gateway pods can take well over the
		// usual 5 minutes. Allow plenty of headroom.
		By("waiting for 3 gateway pods to register in the layout")
		Eventually(func(g Gomega) {
			out, err := utils.Run(exec.Command("kubectl", "get", "garageclusters.v1beta2.garage.rajsingh.info", v2ScaleCluster, "-n", testNS,
				"-o", "jsonpath={.status.gatewayReadyReplicas}"))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal("3"), "expected 3 gateway-ready replicas, got %q", out)
		}, 10*time.Minute, 10*time.Second).Should(Succeed())

		By("scaling gateway tier from 3 -> 1")
		_, err = utils.Run(exec.Command("kubectl", "patch", "garageclusters.v1beta2.garage.rajsingh.info", v2ScaleCluster, "-n", testNS,
			"--type=merge", "-p", `{"spec":{"gateway":{"replicas":1}}}`))
		Expect(err).NotTo(HaveOccurred())

		By("waiting for both serialized gateway drains and Garage layout history to settle")
		Eventually(func(g Gomega) {
			gatewayTopologyConverged(g, 1)
		}, 15*time.Minute, 10*time.Second).Should(Succeed())

		By("scaling gateway tier back from 1 -> 3")
		_, err = utils.Run(exec.Command("kubectl", "patch", "garageclusters.v1beta2.garage.rajsingh.info", v2ScaleCluster, "-n", testNS,
			"--type=merge", "-p", `{"spec":{"gateway":{"replicas":3}}}`))
		Expect(err).NotTo(HaveOccurred())

		Eventually(func(g Gomega) {
			gatewayTopologyConverged(g, 3)
		}, 10*time.Minute, 10*time.Second).Should(Succeed())
	})

	// Scenario 11: persistent identity preservation on gateway pod replacement
	// (v0.5.6+). The metadata PVC pinned to the StatefulSet replica re-mounts
	// when the pod is replaced, so Garage keeps the same node_key and the
	// cluster layout does not gain a new entry.
	It("preserves the gateway node ID across pod restart (no layout churn)", func() {
		// See scenario 8: PSA restricted requires explicit securityContext.
		yaml := fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: %s
  namespace: %s
spec:
  replication: {factor: 1}
  storage:
    replicas: 1
    metadata: {size: 1Gi}
    data:     {size: 1Gi}
    resources: {limits: {memory: 256Mi}, requests: {memory: 128Mi}}
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
    resources: {limits: {memory: 256Mi}, requests: {memory: 64Mi}}
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
  layoutManagement:
    autoApply: true
  admin:
    adminTokenSecretRef: {name: %s, key: admin-token}
  security: {allowInsecureSecretPermissions: true}
`, v2RotationCluster, testNS, adminTokenSecret)
		applyManifest(yaml, "apply gateway rotation fixture")
		var err error

		By("waiting for the initial gateway pod to register and capturing its exact layout identity")
		var initialID string
		var initialLayoutVersion uint64
		Eventually(func(g Gomega) {
			out, err := utils.Run(exec.Command("kubectl", "get", "garageclusters.v1beta2.garage.rajsingh.info", v2RotationCluster, "-n", testNS,
				"-o", "jsonpath={.status.gatewayReadyReplicas}"))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal("1"))

			layout, history := readGarageLayoutSnapshot(
				g, testNS, "dual-version-rotation-layout", v2RotationCluster, adminTokenValue,
			)
			gatewayIDs := gatewayRoleIDs(layout)
			g.Expect(gatewayIDs).To(HaveLen(1),
				"expected one committed gateway role, got %v", gatewayIDs)
			g.Expect(layout.StagedRoleChanges).To(BeEmpty(),
				"initial gateway layout still has staged changes")
			g.Expect(history.MinAck).To(BeNumerically(">=", history.CurrentVersion),
				"initial gateway layout is not acknowledged by every node")
			for _, version := range history.Versions {
				g.Expect(version.Status).NotTo(Equal("Draining"),
					"initial gateway layout version %d is still draining", version.Version)
			}
			initialID = gatewayIDs[0]
			initialLayoutVersion = layout.Version
		}, 5*time.Minute, 5*time.Second).Should(Succeed())

		Expect(initialID).NotTo(BeEmpty())
		var gatewayPodName string
		gatewaySelector := "app.kubernetes.io/instance=" + v2RotationCluster + ",garage.rajsingh.info/tier=gateway"
		Eventually(func(g Gomega) {
			var err error
			gatewayPodName, err = e2ePodName(testNS, gatewaySelector, true)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(gatewayPodName).NotTo(BeEmpty())
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("deleting the exact gateway pod to trigger a replacement")
		_, err = utils.Run(exec.Command("kubectl", "delete", "pod", gatewayPodName, "-n", testNS,
			"--wait=true", "--timeout=2m"))
		Expect(err).NotTo(HaveOccurred())

		By("expecting the replacement pod to reuse the same layout identity without churn")
		Eventually(func(g Gomega) {
			out, err := utils.Run(exec.Command("kubectl", "get", "garageclusters.v1beta2.garage.rajsingh.info", v2RotationCluster, "-n", testNS,
				"-o", "jsonpath={.status.pendingGatewayTombstones}"))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Or(Equal(""), Equal("[]")), "unexpected gateway tombstone, got %q", out)

			replacementPod, err := e2ePodName(testNS, gatewaySelector, true)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(replacementPod).To(Equal(gatewayPodName),
				"StatefulSet replacement did not restore the same ordinal Pod")
			out, err = utils.Run(exec.Command("kubectl", "get", "garageclusters.v1beta2.garage.rajsingh.info", v2RotationCluster, "-n", testNS,
				"-o", "jsonpath={.status.gatewayReadyReplicas}"))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal("1"))

			layout, history := readGarageLayoutSnapshot(
				g, testNS, "dual-version-rotation-layout", v2RotationCluster, adminTokenValue,
			)
			gatewayIDs := gatewayRoleIDs(layout)
			g.Expect(gatewayIDs).To(Equal([]string{initialID}),
				"gateway layout identity changed across restart")
			g.Expect(layout.Version).To(Equal(initialLayoutVersion),
				"gateway restart caused an unnecessary layout version")
			g.Expect(history.CurrentVersion).To(Equal(initialLayoutVersion))
			g.Expect(history.MinAck).To(BeNumerically(">=", history.CurrentVersion),
				"replacement gateway has not acknowledged the current layout")
			g.Expect(layout.StagedRoleChanges).To(BeEmpty(),
				"gateway restart left a staged layout change")
		}, 5*time.Minute, 10*time.Second).Should(Succeed())
	})

	// Scenario 12: explicit representationally incomplete v1beta1 projection of
	// a unified v1beta2 CR. Its reserved payload keeps the actual round-trip
	// lossless; this assertion covers the visible marker.
	It("annotates the v1beta1 view of a unified v1beta2 CR with the v1beta2-only marker", func() {
		// v2Unified was created in scenario 3 with both storage and gateway tiers.
		By("reading via v1beta1 endpoint and inspecting the annotation")
		var out string
		Eventually(func(g Gomega) {
			get := exec.Command("kubectl", "get", "garageclusters.v1beta1.garage.rajsingh.info", v2Unified, "-n", testNS,
				"-o", "jsonpath={.metadata.annotations."+strings.ReplaceAll(v1beta2LossyAnnotation, ".", "\\.")+"}")
			var err error
			out, err = utils.Run(get)
			g.Expect(err).NotTo(HaveOccurred())
			out = stripKubectlWarnings(out)
			g.Expect(out).To(Equal("gateway-tier-present"),
				"v1beta1 view of unified CR should be annotated with v1beta2-only marker; got %q", out)
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	})
})
