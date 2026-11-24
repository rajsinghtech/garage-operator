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
	"sort"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rajsinghtech/garage-operator/test/utils"
)

// GarageReplication end to end: two independent single-node GarageClusters in
// one Kind cluster, the operator started with --enable-replication, and real
// rclone Jobs in a restricted namespace. Covers the not-reconciled warning,
// the credentials opt-in, Copy, destination exclusivity, Mirror's first-run
// trigger, both safety guards with their hold and release, and the migration
// sequence of the design record (scheduled Copy, final Mirror + Check on a
// trigger, suspend).
var _ = Describe("GarageReplication", Ordered, Label("replication"), func() {
	const (
		testNamespace = "garage-replication-e2e"
		srcCluster    = "repl-src"
		dstCluster    = "repl-dst"
		adminToken    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		// Keys: the writers seed and inspect buckets from aws-cli; the reader
		// is the least-privilege source key. Only the reader and the
		// destination writer opt in to replication.
		srcWriter = "src-writer"
		srcReader = "src-reader"
		dstWriter = "dst-writer"
	)
	srcEndpoint := fmt.Sprintf("http://%s.%s.svc.cluster.local:3900", srcCluster, testNamespace)
	dstEndpoint := fmt.Sprintf("http://%s.%s.svc.cluster.local:3900", dstCluster, testNamespace)

	apply := func(yaml string) string {
		GinkgoHelper()
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(yaml)
		out, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "kubectl apply: %s", out)
		return out
	}
	jsonpath := func(g Gomega, resource, name, path string) string {
		out, err := utils.Run(exec.Command("kubectl", "get", resource, name, "-n", testNamespace,
			"-o", "jsonpath="+path))
		g.Expect(err).NotTo(HaveOccurred(), "reading %s/%s %s: %s", resource, name, path, out)
		return strings.TrimSpace(out)
	}
	annotate := func(name, value string) {
		GinkgoHelper()
		out, err := utils.Run(exec.Command("kubectl", "annotate", "--overwrite", "garagereplication", name,
			"-n", testNamespace, "garage.rajsingh.info/trigger-sync="+value))
		Expect(err).NotTo(HaveOccurred(), "trigger-sync on %s: %s", name, out)
	}
	patch := func(name, merge string) {
		GinkgoHelper()
		out, err := utils.Run(exec.Command("kubectl", "patch", "garagereplication", name,
			"-n", testNamespace, "--type=merge", "-p", merge))
		Expect(err).NotTo(HaveOccurred(), "patch %s: %s", name, out)
	}
	// s3 runs an aws-cli script against an endpoint with a key's Secret.
	s3 := func(podName, endpoint, key, script string) string {
		GinkgoHelper()
		var out string
		Eventually(func(g Gomega) {
			out = runAWSCLI(g, testNamespace, podName,
				fmt.Sprintf("export E=%s; %s", endpoint, script), key, true)
		}, 3*time.Minute, 10*time.Second).Should(Succeed())
		return out
	}
	put := func(endpoint, key, bucket string, objects ...string) {
		GinkgoHelper()
		script := make([]string, 0, len(objects))
		for _, o := range objects {
			script = append(script, fmt.Sprintf(
				"printf %%s %s > /tmp/o && aws s3api put-object --endpoint-url $E --region garage --bucket %s --key %s --body /tmp/o >/dev/null",
				shellQuote(o), bucket, o))
		}
		s3("repl-put", endpoint, key, strings.Join(script, " && "))
	}
	remove := func(endpoint, key, bucket string, objects ...string) {
		GinkgoHelper()
		script := make([]string, 0, len(objects))
		for _, o := range objects {
			script = append(script, fmt.Sprintf(
				"aws s3api delete-object --endpoint-url $E --region garage --bucket %s --key %s", bucket, o))
		}
		s3("repl-delete", endpoint, key, strings.Join(script, " && "))
	}
	list := func(endpoint, key, bucket string) []string {
		GinkgoHelper()
		out := s3("repl-list", endpoint, key, fmt.Sprintf(
			"echo BEGIN; aws s3api list-objects-v2 --endpoint-url $E --region garage --bucket %s --query 'Contents[].Key' --output text; echo END",
			bucket))
		begin, end := strings.Index(out, "BEGIN"), strings.LastIndex(out, "END")
		Expect(begin).To(BeNumerically(">=", 0), "no listing in %q", out)
		var keys []string
		for _, k := range strings.Fields(out[begin+len("BEGIN") : end]) {
			if k != "None" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		return keys
	}
	// waitRun waits for a finished run started by trigger value (or by
	// anything when trigger is empty) and returns its result.
	waitRun := func(name, trigger string, timeout time.Duration) string {
		GinkgoHelper()
		var result string
		Eventually(func(g Gomega) {
			g.Expect(jsonpath(g, "garagereplication", name, "{.status.currentRun}")).To(BeEmpty(), "a run is in progress")
			if trigger != "" {
				g.Expect(jsonpath(g, "garagereplication", name, "{.status.lastRun.trigger}")).To(Equal(trigger))
			}
			result = jsonpath(g, "garagereplication", name, "{.status.lastRun.result}")
			g.Expect(result).NotTo(BeEmpty())
		}, timeout, 5*time.Second).Should(Succeed())
		return result
	}
	bucketField := func(g Gomega, name, destination, field string) string {
		return jsonpath(g, "garagereplication", name,
			fmt.Sprintf(`{.status.buckets[?(@.destination=="%s")].%s}`, destination, field))
	}
	replication := func(name, mode, extra string, buckets ...[2]string) string {
		var b strings.Builder
		for _, pair := range buckets {
			fmt.Fprintf(&b, "    - source: %s\n      destination: %s\n", pair[0], pair[1])
		}
		return fmt.Sprintf(`
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageReplication
metadata:
  name: %s
  namespace: %s
spec:
  source:
    clusterRef: {name: %s}
    credentialsSecretRef: {name: %s}
  destination:
    clusterRef: {name: %s}
    credentialsSecretRef: {name: %s}
  mode: %s
%s  buckets:
%s`, name, testNamespace, srcCluster, srcReader, dstCluster, dstWriter, mode, extra, b.String())
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

		By("deploying the controller-manager (replication disabled, the default)")
		_, err = utils.Run(exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage)))
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
		Expect(waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())
		Eventually(func(g Gomega) {
			_, err := controllerManagerPodReady(namespace)
			g.Expect(err).NotTo(HaveOccurred(), "Controller not Ready")
		}, 3*time.Minute, 5*time.Second).Should(Succeed())

		By("creating the restricted test namespace (replication Jobs must pass it)")
		Expect(createE2ETestNamespace(testNamespace)).To(Succeed())
		_, err = utils.Run(exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
			"pod-security.kubernetes.io/enforce=restricted"))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		By("deleting GarageReplications (their Jobs are garbage-collected)")
		output, err := utils.Run(exec.Command("kubectl", "delete", "garagereplication", "--all", "-n", testNamespace,
			"--ignore-not-found", "--wait=false"))
		if err != nil {
			reportE2ECleanupWait("replication GarageReplication delete request", fmt.Errorf("%v: %s", err, output))
		}
		reportE2ECleanupWait("replication GarageReplications", waitForE2EResourcesDeleted(
			"garagereplication", testNamespace, "", 2*time.Minute,
		))
		cleanupManagementHandle(testNamespace, []string{srcCluster, dstCluster})
		output, err = utils.Run(exec.Command("make", "undeploy"))
		if err != nil {
			reportE2ECleanupWait("make undeploy", fmt.Errorf("%v: %s", err, output))
		}
		output, err = utils.Run(exec.Command("make", "uninstall", "ignore-not-found=true"))
		if err != nil {
			reportE2ECleanupWait("make uninstall", fmt.Errorf("%v: %s", err, output))
		}
		finishE2ECleanupWaits()
	})

	It("stands up two independent clusters, buckets and keys", func() {
		apply(fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: garage-admin-token
  namespace: %s
type: Opaque
stringData:
  admin-token: %q
`, testNamespace, adminToken))
		for _, name := range []string{srcCluster, dstCluster} {
			yaml := fmt.Sprintf(`
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
    metadata: {size: 1Gi}
    data: {size: 1Gi}
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
    adminTokenSecretRef: {name: garage-admin-token, key: admin-token}
  security:
    allowInsecureSecretPermissions: true
`, name, testNamespace)
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "apply", "-f", "-")
				cmd.Stdin = strings.NewReader(yaml)
				out, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "GarageCluster %s: %s", name, out)
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
		}
		for _, name := range []string{srcCluster, dstCluster} {
			Eventually(func(g Gomega) {
				g.Expect(jsonpath(g, "garagecluster", name, "{.status.phase}")).To(Equal("Running"))
			}, 6*time.Minute, 5*time.Second).Should(Succeed())
		}

		By("creating buckets on each cluster (same alias on both sides for medias)")
		var buckets strings.Builder
		for _, b := range []struct{ name, cluster, alias string }{
			{"src-medias", srcCluster, "medias"}, {"src-mirror", srcCluster, "mirror-src"}, {"src-empty", srcCluster, "empty-src"},
			{"dst-medias", dstCluster, "medias"}, {"dst-mirror", dstCluster, "mirror-dst"}, {"dst-guarded", dstCluster, "guarded"},
		} {
			fmt.Fprintf(&buckets, `---
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef: {name: %s}
  globalAlias: %s
  deletionPolicy: Retain
`, b.name, testNamespace, b.cluster, b.alias)
		}
		apply(buckets.String())

		By("creating keys: an opted-in read-only source key and opted-in destination writer")
		optIn := "  secretTemplate:\n    labels:\n      garage.rajsingh.info/replication-credentials: \"true\"\n"
		key := func(name, cluster, labels string, write bool, bucketRefs ...string) string {
			var perms strings.Builder
			for _, b := range bucketRefs {
				fmt.Fprintf(&perms, "    - bucketRef: {name: %s}\n      read: true\n      write: %t\n", b, write)
			}
			return fmt.Sprintf(`---
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: %s
  namespace: %s
spec:
  clusterRef: {name: %s}
%s  bucketPermissions:
%s`, name, testNamespace, cluster, labels, perms.String())
		}
		apply(key(srcWriter, srcCluster, "", true, "src-medias", "src-mirror", "src-empty") +
			key(srcReader, srcCluster, optIn, false, "src-medias", "src-mirror", "src-empty") +
			key(dstWriter, dstCluster, optIn, true, "dst-medias", "dst-mirror", "dst-guarded"))
		for _, name := range []string{"src-medias", "src-mirror", "src-empty", "dst-medias", "dst-mirror", "dst-guarded"} {
			Eventually(func(g Gomega) {
				g.Expect(jsonpath(g, "garagebucket", name, "{.status.phase}")).To(Equal("Ready"))
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
		}
		for _, name := range []string{srcWriter, srcReader, dstWriter} {
			Eventually(func(g Gomega) {
				g.Expect(jsonpath(g, "garagekey", name, "{.status.phase}")).To(Equal("Ready"))
				g.Expect(jsonpath(g, "secret", name, "{.metadata.name}")).To(Equal(name))
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
		}
	})

	It("warns that objects are not reconciled while the controller is disabled", func() {
		out := apply(replication("not-yet", "Copy", "", [2]string{"medias", "medias"}))
		Expect(out).To(ContainSubstring("--enable-replication"), "admission should warn: %s", out)
		Consistently(func(g Gomega) {
			g.Expect(jsonpath(g, "garagereplication", "not-yet", "{.status.phase}")).To(BeEmpty())
		}, 15*time.Second, 5*time.Second).Should(Succeed())
		output, err := utils.Run(exec.Command("kubectl", "delete", "garagereplication", "not-yet", "-n", testNamespace))
		Expect(err).NotTo(HaveOccurred(), "delete: %s", output)

		By("enabling the replication controller")
		output, err = utils.Run(exec.Command("kubectl", "set", "env", "deployment/garage-operator-controller-manager",
			"-n", namespace, "ENABLE_REPLICATION=true"))
		Expect(err).NotTo(HaveOccurred(), "set env: %s", output)
		output, err = utils.Run(exec.Command("kubectl", "rollout", "status", "deployment/garage-operator-controller-manager",
			"-n", namespace, "--timeout=3m"))
		Expect(err).NotTo(HaveOccurred(), "rollout: %s", output)
		Expect(waitForE2EWebhookRoute(namespace, 2*time.Minute)).To(Succeed())
		Eventually(func(g Gomega) {
			_, err := controllerManagerPodReady(namespace)
			g.Expect(err).NotTo(HaveOccurred(), "Controller not Ready")
		}, 3*time.Minute, 5*time.Second).Should(Succeed())
	})

	It("refuses credentials Secrets that did not opt in", func() {
		yaml := strings.Replace(replication("not-opted-in", "Copy", "", [2]string{"medias", "medias"}),
			"credentialsSecretRef: {name: "+srcReader+"}", "credentialsSecretRef: {name: "+srcWriter+"}", 1)
		out := apply(yaml)
		Expect(out).NotTo(ContainSubstring("--enable-replication"), "the controller is enabled now: %s", out)
		Eventually(func(g Gomega) {
			g.Expect(jsonpath(g, "garagereplication", "not-opted-in",
				`{.status.conditions[?(@.type=="Ready")].reason}`)).To(Equal("CredentialsNotAllowed"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
		out, err := utils.Run(exec.Command("kubectl", "get", "job", "-n", testNamespace, "-o", "name"))
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(out)).To(BeEmpty(), "no Job may run with a Secret that did not opt in")
		output, err := utils.Run(exec.Command("kubectl", "delete", "garagereplication", "not-opted-in", "-n", testNamespace))
		Expect(err).NotTo(HaveOccurred(), "delete: %s", output)
	})

	It("copies a bucket in Copy mode with a read-only source key", func() {
		put(srcEndpoint, srcWriter, "medias", "a.txt", "b.txt")
		apply(replication("medias", "Copy", "", [2]string{"medias", "medias"}))
		Expect(waitRun("medias", "", 5*time.Minute)).To(Equal("Succeeded"))
		Eventually(func(g Gomega) {
			g.Expect(jsonpath(g, "garagereplication", "medias", `{.status.conditions[?(@.type=="Synced")].status}`)).To(Equal("True"))
			g.Expect(bucketField(g, "medias", "medias", "lastStatistics.transfers")).To(Equal("2"))
		}, time.Minute, 5*time.Second).Should(Succeed())
		Expect(list(dstEndpoint, dstWriter, "medias")).To(Equal([]string{"a.txt", "b.txt"}))
	})

	It("rejects a second GarageReplication writing the same destination bucket", func() {
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(replication("medias-again", "Copy", "", [2]string{"mirror-src", "medias"}))
		out, err := utils.Run(cmd)
		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring(`already written by GarageReplication "medias"`))
	})

	It("holds Mirror until a trigger, then holds again on maxDeletes until the next trigger", func() {
		put(srcEndpoint, srcWriter, "mirror-src", "a.txt", "b.txt", "c.txt")
		apply(replication("mirror", "Mirror", "  mirror: {maxDeletes: 1}\n  verification: Check\n", [2]string{"mirror-src", "mirror-dst"}))

		By("waiting for the first Mirror run to be held")
		Eventually(func(g Gomega) {
			g.Expect(bucketField(g, "mirror", "mirror-dst", "hold")).To(Equal("AwaitingTrigger"))
			g.Expect(jsonpath(g, "garagereplication", "mirror", `{.status.conditions[?(@.type=="Synced")].reason}`)).To(Equal("AwaitingTrigger"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
		out, err := utils.Run(exec.Command("kubectl", "get", "job", "-n", testNamespace,
			"-l", "app.kubernetes.io/instance=mirror", "-o", "name"))
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(out)).To(BeEmpty(), "the first Mirror run must wait for a trigger")

		By("triggering the first Mirror run")
		annotate("mirror", "first")
		Expect(waitRun("mirror", "first", 5*time.Minute)).To(Equal("Succeeded"))
		Expect(list(dstEndpoint, dstWriter, "mirror-dst")).To(Equal([]string{"a.txt", "b.txt", "c.txt"}))

		By("deleting two source objects with maxDeletes 1")
		remove(srcEndpoint, srcWriter, "mirror-src", "a.txt", "b.txt")
		annotate("mirror", "second")
		Expect(waitRun("mirror", "second", 5*time.Minute)).To(Equal("Failed"))
		Eventually(func(g Gomega) {
			g.Expect(bucketField(g, "mirror", "mirror-dst", "hold")).To(Equal("MaxDeletesExceeded"))
			g.Expect(bucketField(g, "mirror", "mirror-dst", "lastError")).To(Equal("MaxDeletesExceeded"))
		}, time.Minute, 5*time.Second).Should(Succeed())
		Expect(list(dstEndpoint, dstWriter, "mirror-dst")).To(HaveLen(2), "one deletion allowed")

		By("raising maxDeletes: a spec edit must not release the hold")
		patch("mirror", `{"spec":{"mirror":{"maxDeletes":10},"schedule":"* * * * *"}}`)
		Consistently(func(g Gomega) {
			g.Expect(bucketField(g, "mirror", "mirror-dst", "hold")).To(Equal("MaxDeletesExceeded"))
			g.Expect(jsonpath(g, "garagereplication", "mirror", "{.status.currentRun}")).To(BeEmpty())
		}, 90*time.Second, 10*time.Second).Should(Succeed())

		By("releasing the hold with trigger-sync (suspended first, so no scheduled run follows it)")
		patch("mirror", `{"spec":{"suspend":true}}`)
		annotate("mirror", "third")
		Expect(waitRun("mirror", "third", 5*time.Minute)).To(Equal("Succeeded"))
		Eventually(func(g Gomega) {
			g.Expect(bucketField(g, "mirror", "mirror-dst", "hold")).To(BeEmpty())
			g.Expect(bucketField(g, "mirror", "mirror-dst", "lastVerification")).To(Equal("Passed"))
		}, time.Minute, 5*time.Second).Should(Succeed())
		Expect(list(dstEndpoint, dstWriter, "mirror-dst")).To(Equal([]string{"c.txt"}))
	})

	It("never lets an empty source wipe a non-empty destination", func() {
		put(dstEndpoint, dstWriter, "guarded", "keep.txt")
		apply(replication("guard", "Mirror", "  mirror: {maxDeletes: 100}\n", [2]string{"empty-src", "guarded"}))
		annotate("guard", "checked")
		Expect(waitRun("guard", "checked", 5*time.Minute)).To(Equal("Failed"))
		Eventually(func(g Gomega) {
			g.Expect(bucketField(g, "guard", "guarded", "hold")).To(Equal("SourceEmpty"))
			g.Expect(jsonpath(g, "garagereplication", "guard", `{.status.conditions[?(@.type=="Synced")].reason}`)).To(Equal("SafetyHold"))
		}, time.Minute, 5*time.Second).Should(Succeed())
		Expect(list(dstEndpoint, dstWriter, "guarded")).To(Equal([]string{"keep.txt"}))
	})

	It("runs the migration sequence: scheduled Copy, final Mirror with Check on a trigger, suspend", func() {
		By("keeping the destination close with scheduled Copy runs while the source is written")
		patch("medias", `{"spec":{"schedule":"* * * * *"}}`)
		put(srcEndpoint, srcWriter, "medias", "c.txt")
		Eventually(func(g Gomega) {
			g.Expect(list(dstEndpoint, dstWriter, "medias")).To(ContainElement("c.txt"))
		}, 4*time.Minute, 15*time.Second).Should(Succeed())

		By("freezing writes, then the final sync: Mirror + Check on a trigger")
		remove(srcEndpoint, srcWriter, "medias", "a.txt")
		// The schedule goes away: the final sync runs on the trigger only.
		patch("medias", `{"metadata":{"annotations":{"garage.rajsingh.info/trigger-sync":"final"}},`+
			`"spec":{"schedule":null,"mode":"Mirror","mirror":{"maxDeletes":100},"verification":"Check"}}`)
		Expect(waitRun("medias", "final", 5*time.Minute)).To(Equal("Succeeded"))
		Eventually(func(g Gomega) {
			g.Expect(bucketField(g, "medias", "medias", "lastMode")).To(Equal("Mirror"))
			g.Expect(bucketField(g, "medias", "medias", "lastVerification")).To(Equal("Passed"))
			g.Expect(bucketField(g, "medias", "medias", "lastStatistics.differences")).To(Equal("0"))
			g.Expect(jsonpath(g, "garagereplication", "medias", `{.status.conditions[?(@.type=="Synced")].status}`)).To(Equal("True"))
		}, time.Minute, 5*time.Second).Should(Succeed())
		Expect(list(dstEndpoint, dstWriter, "medias")).To(Equal(list(srcEndpoint, srcWriter, "medias")))

		By("suspending after the cutover")
		patch("medias", `{"spec":{"suspend":true}}`)
		Eventually(func(g Gomega) {
			g.Expect(jsonpath(g, "garagereplication", "medias", "{.status.phase}")).To(Equal("Suspended"))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
	})
})
