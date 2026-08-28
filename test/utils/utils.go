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

package utils

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2" // nolint:revive,staticcheck
)

const (
	certmanagerVersion     = "v1.19.1"
	certmanagerManifestSHA = "876a41a57e36b85619f4124b24b3deb80912b5ffed515f90e2f160b6e6338e81"
	certmanagerURLTmpl     = "https://github.com/cert-manager/cert-manager/releases/download/%s/cert-manager.yaml"
	certmanagerMaxBytes    = 20 << 20

	defaultKindBinary  = "kind"
	defaultKindCluster = "kind"
)

func bindKubectlContext(cmd *exec.Cmd) error {
	if cmd == nil || len(cmd.Args) == 0 || filepath.Base(cmd.Args[0]) != kubectlBinary {
		return nil
	}
	cluster := strings.TrimSpace(os.Getenv("KIND_CLUSTER"))
	if cluster == "" {
		return nil
	}
	expected := "kind-" + cluster
	for i, arg := range cmd.Args[1:] {
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "--context=") {
			if contextName := strings.TrimPrefix(arg, "--context="); contextName != expected {
				return fmt.Errorf("refusing kubectl context %q during Kind E2E; expected %q", contextName, expected)
			}
			return nil
		}
		if arg == "--context" {
			index := i + 2
			if index >= len(cmd.Args) || cmd.Args[index] != expected {
				actual := ""
				if index < len(cmd.Args) {
					actual = cmd.Args[index]
				}
				return fmt.Errorf("refusing kubectl context %q during Kind E2E; expected %q", actual, expected)
			}
			return nil
		}
	}
	args := make([]string, 0, len(cmd.Args)+1)
	args = append(args, cmd.Args[0], "--context="+expected)
	cmd.Args = append(args, cmd.Args[1:]...)
	return nil
}

var certmanagerImagePins = map[string]string{
	"quay.io/jetstack/cert-manager-controller:v1.19.1": "quay.io/jetstack/cert-manager-controller:v1.19.1@sha256:cd49e769e18ada1fd7b9a9bacc87c90db24c65cbfd4bf71694dda7ed40e91187",
	"quay.io/jetstack/cert-manager-cainjector:v1.19.1": "quay.io/jetstack/cert-manager-cainjector:v1.19.1@sha256:c7898aece8fb08102fca0b37683e37cb94e0a77c0d15b8e3c9128f6c04c868e0",
	"quay.io/jetstack/cert-manager-webhook:v1.19.1":    "quay.io/jetstack/cert-manager-webhook:v1.19.1@sha256:f5bfe77541e38978aec53cc6eb924d190e1fe923c98b2582e6ccf5edf6c02cce",
	"quay.io/jetstack/cert-manager-acmesolver:v1.19.1": "quay.io/jetstack/cert-manager-acmesolver:v1.19.1@sha256:35ed1103cb49a3e1fc2438de84f304e3fbdeb53e0366f6b1bc2ec9b2e57462db",
}

func warnError(err error) {
	_, _ = fmt.Fprintf(GinkgoWriter, "warning: %v\n", err)
}

var certmanagerManifestCache struct {
	once    sync.Once
	payload []byte
	err     error
}

// certManagerManifest returns the exact cert-manager release manifest expected
// by the E2E suite. It is downloaded and verified at most once so apply and
// teardown consume identical bytes without teardown depending on the network.
// The immutable in-memory cache is safe for concurrent callers and is reclaimed
// automatically when the test process exits.
func certManagerManifest() ([]byte, error) {
	certmanagerManifestCache.once.Do(func() {
		certmanagerManifestCache.payload, certmanagerManifestCache.err = downloadCertManagerManifest()
	})
	return certmanagerManifestCache.payload, certmanagerManifestCache.err
}

func downloadCertManagerManifest() ([]byte, error) {
	url := fmt.Sprintf(certmanagerURLTmpl, certmanagerVersion)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create cert-manager manifest request: %w", err)
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	response, err := client.Do(request) // #nosec G107 -- fixed HTTPS release URL
	if err != nil {
		return nil, fmt.Errorf("download cert-manager manifest: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download cert-manager manifest: HTTP %s", response.Status)
	}

	payload, err := io.ReadAll(io.LimitReader(response.Body, certmanagerMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read cert-manager manifest: %w", err)
	}
	if len(payload) > certmanagerMaxBytes {
		return nil, fmt.Errorf("cert-manager manifest exceeds %d bytes", certmanagerMaxBytes)
	}
	if digest := fmt.Sprintf("%x", sha256.Sum256(payload)); digest != certmanagerManifestSHA {
		return nil, fmt.Errorf("cert-manager manifest checksum %s, want %s", digest, certmanagerManifestSHA)
	}
	return pinCertManagerImages(payload)
}

func pinCertManagerImages(payload []byte) ([]byte, error) {
	pinned := bytes.Clone(payload)
	for source, target := range certmanagerImagePins {
		if bytes.Count(pinned, []byte(source)) != 1 {
			return nil, fmt.Errorf("cert-manager manifest must contain image %q exactly once", source)
		}
		pinned = bytes.ReplaceAll(pinned, []byte(source), []byte(target))
	}

	scanner := bufio.NewScanner(bytes.NewReader(pinned))
	scanner.Buffer(make([]byte, 64*1024), certmanagerMaxBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		image := ""
		if strings.HasPrefix(line, "image:") {
			image = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "image:")), `"'`)
		} else {
			argument := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "- ")), `"'`)
			if equals := strings.IndexByte(argument, '='); equals > 2 &&
				strings.HasPrefix(argument, "--") && strings.HasSuffix(argument[:equals], "-image") {
				image = strings.Trim(argument[equals+1:], `"'`)
			}
		}
		if image != "" && !isSHA256DigestPinned(image) {
			return nil, fmt.Errorf("cert-manager manifest contains image without digest: %s", image)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan cert-manager manifest images: %w", err)
	}
	return pinned, nil
}

func isSHA256DigestPinned(image string) bool {
	const separator = "@sha256:"
	index := strings.LastIndex(image, separator)
	if index < 1 || len(image[index+len(separator):]) != 64 {
		return false
	}
	for _, character := range image[index+len(separator):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

const (
	// defaultKubectlDeleteTimeout bounds any `kubectl delete` the suite issues
	// without saying how long it is willing to wait.
	//
	// Garage finalizers are fail-closed: a GarageCluster whose Admin API it cannot
	// reach, or whose layout it cannot prove safe to release, blocks deletion
	// indefinitely. An unbounded delete in a teardown hook inherits that block, and
	// because teardown runs inside the same `go test` process it consumes the rest of
	// the shard's budget. The result reports as "panic: test timed out after 40m"
	// attributed to whichever cleanup line happened to be executing, hiding both the
	// stuck finalizer and every spec that never got to run — twice observed on this
	// suite, in two different shards.
	//
	// The delete is still issued and processed asynchronously; the suite just
	// stops blocking on an unbounded finalizer or API request. Callers that need
	// to assert a delete completed keep doing so with their own Eventually.
	defaultKubectlDeleteTimeout  = "3m"
	defaultKubectlRequestTimeout = "15s"

	// CLI clients can hang below their own API deadlines while waiting on a
	// daemon, a child process, or an inherited output pipe. Keep those clients
	// bounded at a layer outside the client as well. The values are deliberately
	// longer than the operation-specific flags used by the suite.
	defaultKubectlExecutionTimeout = 6 * time.Minute
	defaultDockerExecTimeout       = 2 * time.Minute
	defaultDockerBuildTimeout      = 15 * time.Minute
	defaultKindQueryTimeout        = 30 * time.Second
	defaultKindOperationTimeout    = 10 * time.Minute
	defaultHelmInstallTimeout      = 6 * time.Minute
	defaultHelmUninstallTimeout    = 4 * time.Minute
	defaultMakeTimeout             = 10 * time.Minute
	defaultMakeBuildTimeout        = 15 * time.Minute

	kubectlBinary     = "kubectl"
	kubectlDeleteVerb = "delete"
)

// kubectlVerb returns kubectl's subcommand while accounting for global flags
// that take a separate value. Command-specific flags appear after the verb in
// every command used by the E2E helpers and therefore do not affect this scan.
func kubectlVerb(args []string) string {
	if len(args) < 2 || filepath.Base(args[0]) != kubectlBinary {
		return ""
	}

	skipNext := false
	for _, arg := range args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		switch arg {
		case "--context", "--kubeconfig", "--namespace", "-n", "--server", "--as", "--as-group", "--as-user", "--as-uid", "--cluster", "--user", "--token", "--certificate-authority", "--client-certificate", "--client-key", "--cache-dir", "--request-timeout", "-f":
			skipNext = true
			continue
		case "--":
			return ""
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg
	}
	return ""
}

func hasKubectlRequestTimeout(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "--request-timeout" || strings.HasPrefix(arg, "--request-timeout=") {
			return true
		}
	}
	return false
}

// boundKubectlDelete bounds both sides of a kubectl delete. A regular delete
// gets a deadline for waiting on object disappearance and an API request
// deadline; a --wait=false delete gets only the request deadline because it
// intentionally does not wait for object disappearance.
func boundKubectlDelete(cmd *exec.Cmd) {
	if cmd == nil || len(cmd.Args) < 2 || filepath.Base(cmd.Args[0]) != kubectlBinary {
		return
	}
	if kubectlVerb(cmd.Args) != kubectlDeleteVerb {
		return
	}
	waitFalse := false
	requestTimeout := false
	deleteTimeout := false
	for _, arg := range cmd.Args {
		if arg == "--" {
			break
		}
		if arg == "--timeout" || strings.HasPrefix(arg, "--timeout=") {
			deleteTimeout = true
		}
		if arg == "--request-timeout" || strings.HasPrefix(arg, "--request-timeout=") {
			requestTimeout = true
		}
		if arg == "--wait=false" {
			waitFalse = true
		}
	}
	if waitFalse {
		if !requestTimeout {
			cmd.Args = append(cmd.Args, "--request-timeout="+defaultKubectlRequestTimeout)
		}
		return
	}
	if !deleteTimeout {
		cmd.Args = append(cmd.Args, "--timeout="+defaultKubectlDeleteTimeout)
	}
	if !requestTimeout {
		cmd.Args = append(cmd.Args, "--request-timeout="+defaultKubectlRequestTimeout)
	}
}

// boundKubectlRequest adds a finite API request deadline to one-shot kubectl
// operations. Long-lived watch/stream commands deliberately remain untouched:
// `kubectl wait`, following logs, `exec`, `rollout status`, and `port-forward` have
// operation-specific lifetimes and a request timeout would terminate their
// streams before those lifetimes expire. Non-following logs are finite and get
// both a bounded startup wait and API request deadline; callers that use `-f`
// retain only the startup wait. `kubectl exec` and `kubectl run` get the flag
// before their `--` child-command separator so it cannot leak into the child
// command.
func boundKubectlRequest(cmd *exec.Cmd) {
	if cmd == nil || len(cmd.Args) < 2 || filepath.Base(cmd.Args[0]) != kubectlBinary {
		return
	}

	verb := kubectlVerb(cmd.Args)
	if verb == "logs" {
		if !hasKubectlFlag(cmd.Args, "--pod-running-timeout") {
			cmd.Args = append(cmd.Args, "--pod-running-timeout=15s")
		}
		if !hasKubectlFollow(cmd.Args) && !hasKubectlRequestTimeout(cmd.Args) {
			cmd.Args = append(cmd.Args, "--request-timeout="+defaultKubectlRequestTimeout)
		}
		return
	}
	if hasKubectlRequestTimeout(cmd.Args) {
		return
	}
	switch verb {
	case "get", "apply", "create", "patch", "label", "annotate", "delete", "scale", "api-resources", "describe", "cluster-info", "kustomize":
		cmd.Args = append(cmd.Args, "--request-timeout="+defaultKubectlRequestTimeout)
	case "exec", "run":
		separator := len(cmd.Args)
		for index, arg := range cmd.Args {
			if arg == "--" {
				separator = index
				break
			}
		}
		requestTimeout := "--request-timeout=" + defaultKubectlRequestTimeout
		if separator == len(cmd.Args) {
			cmd.Args = append(cmd.Args, requestTimeout)
			return
		}
		cmd.Args = append(cmd.Args, "")
		copy(cmd.Args[separator+1:], cmd.Args[separator:])
		cmd.Args[separator] = requestTimeout
	}
}

func hasKubectlFlag(args []string, flag string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == flag || strings.HasPrefix(arg, flag+"=") {
			return true
		}
	}
	return false
}

func hasKubectlFollow(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "-f" || arg == "--follow" || arg == "--follow=true" {
			return true
		}
	}
	return false
}

// e2eCommandTimeout returns the outer deadline for commands that talk to
// Docker/Kind/Helm or launch a shell through make. Kubectl's own request and
// operation flags remain the source of truth for their normal behavior; this
// outer deadline only protects against a wedged client or daemon. Streaming
// commands are left to their caller because they have no meaningful finite
// completion time.
func e2eCommandTimeout(cmd *exec.Cmd) time.Duration {
	if cmd == nil || len(cmd.Args) == 0 {
		return 0
	}

	switch filepath.Base(cmd.Args[0]) {
	case "kubectl":
		verb := kubectlVerb(cmd.Args)
		if verb == "port-forward" || (verb == "logs" && hasKubectlFollow(cmd.Args)) {
			return 0
		}
		return defaultKubectlExecutionTimeout
	case "docker", "podman":
		if len(cmd.Args) < 2 {
			return defaultDockerExecTimeout
		}
		switch cmd.Args[1] {
		case "build", "save", "load":
			return defaultDockerBuildTimeout
		case "exec":
			return defaultDockerExecTimeout
		default:
			return defaultDockerExecTimeout
		}
	case "kind":
		if len(cmd.Args) >= 2 && cmd.Args[1] == "get" {
			return defaultKindQueryTimeout
		}
		return defaultKindOperationTimeout
	case "helm":
		if len(cmd.Args) >= 2 {
			switch cmd.Args[1] {
			case "install", "upgrade":
				return defaultHelmInstallTimeout
			case "uninstall":
				return defaultHelmUninstallTimeout
			}
		}
		return defaultDockerExecTimeout
	case "make":
		for _, arg := range cmd.Args[1:] {
			if arg == "docker-build" || strings.HasPrefix(arg, "docker-build=") {
				return defaultMakeBuildTimeout
			}
		}
		return defaultMakeTimeout
	case "wait-for-operator-webhook.sh":
		if len(cmd.Args) >= 5 {
			seconds, err := strconv.Atoi(cmd.Args[4])
			if err == nil && seconds > 0 {
				return time.Duration(seconds) * time.Second
			}
		}
		return 2 * time.Minute
	default:
		return 0
	}
}

type synchronizedOutputBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *synchronizedOutputBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *synchronizedOutputBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

// runE2ECommandWithTimeout runs a command through a context while preserving
// the command properties that E2E callers set (working directory, environment,
// stdin, output writers, and extra files). A process group is configured by
// configureE2EProcess so a timed-out make/docker client cannot leave a child
// holding the test process's pipes open.
func runE2ECommandWithTimeout(cmd *exec.Cmd, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	path := cmd.Path
	if path == "" {
		path = cmd.Args[0]
	}
	bounded := exec.CommandContext(ctx, path, cmd.Args[1:]...)
	bounded.Dir = cmd.Dir
	bounded.Env = cmd.Env
	bounded.Stdin = cmd.Stdin
	var captured synchronizedOutputBuffer
	bounded.Stdout = &captured
	if cmd.Stdout != nil {
		bounded.Stdout = io.MultiWriter(&captured, cmd.Stdout)
	}
	bounded.Stderr = &captured
	if cmd.Stderr != nil {
		bounded.Stderr = io.MultiWriter(&captured, cmd.Stderr)
	}
	bounded.ExtraFiles = cmd.ExtraFiles
	configureE2EProcess(bounded)
	// Even a process that ignores SIGKILL can leave an inherited pipe open.
	// WaitDelay ensures CombinedOutput returns instead of waiting forever for
	// such a descriptor.
	bounded.WaitDelay = 5 * time.Second

	err := bounded.Run()
	output := captured.Bytes()
	if err != nil && ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("command timed out after %s: %w", timeout, context.DeadlineExceeded)
	}
	return output, err
}

// Run executes the provided command within this context
func Run(cmd *exec.Cmd) (string, error) {
	dir, _ := GetProjectDir()
	cmd.Dir = dir

	if err := os.Chdir(cmd.Dir); err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "chdir dir: %q\n", err)
	}

	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	if err := bindKubectlContext(cmd); err != nil {
		return "", err
	}
	boundKubectlDelete(cmd)
	boundKubectlRequest(cmd)
	command := strings.Join(cmd.Args, " ")
	_, _ = fmt.Fprintf(GinkgoWriter, "running: %q\n", command)
	var output []byte
	var err error
	if timeout := e2eCommandTimeout(cmd); timeout > 0 {
		output, err = runE2ECommandWithTimeout(cmd, timeout)
	} else {
		output, err = cmd.CombinedOutput()
	}
	if err != nil {
		return string(output), fmt.Errorf("%q failed with error %q: %w", command, string(output), err)
	}

	return string(output), nil
}

// UninstallCertManager uninstalls the cert manager
func UninstallCertManager() {
	manifest, err := certManagerManifest()
	if err != nil {
		warnError(err)
		return
	}

	cmd := exec.Command("kubectl", "delete", "-f", "-", "--timeout=2m", "--wait=false")
	cmd.Stdin = bytes.NewReader(manifest)
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}

	// Delete leftover leases in kube-system (not cleaned by default)
	kubeSystemLeases := []string{
		"cert-manager-cainjector-leader-election",
		"cert-manager-controller",
	}
	for _, lease := range kubeSystemLeases {
		cmd = exec.Command("kubectl", "delete", "lease", lease,
			"-n", "kube-system", "--ignore-not-found", "--force", "--grace-period=0")
		if _, err := Run(cmd); err != nil {
			warnError(err)
		}
	}
}

// InstallCertManager installs the cert manager bundle.
func InstallCertManager() error {
	manifest, err := certManagerManifest()
	if err != nil {
		return err
	}

	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader(manifest)
	if _, err := Run(cmd); err != nil {
		return err
	}
	// Wait for cert-manager-webhook to be ready, which can take time if cert-manager
	// was re-installed after uninstalling on a cluster.
	cmd = exec.Command("kubectl", "wait", "deployment.apps/cert-manager-webhook",
		"--for", "condition=Available",
		"--namespace", "cert-manager",
		"--timeout", "5m",
	)

	_, err = Run(cmd)
	return err
}

// IsCertManagerCRDsInstalled checks if any Cert Manager CRDs are installed
// by verifying the existence of key CRDs related to Cert Manager.
func IsCertManagerCRDsInstalled() bool {
	// List of common Cert Manager CRDs
	certManagerCRDs := []string{
		"certificates.cert-manager.io",
		"issuers.cert-manager.io",
		"clusterissuers.cert-manager.io",
		"certificaterequests.cert-manager.io",
		"orders.acme.cert-manager.io",
		"challenges.acme.cert-manager.io",
	}

	// Execute the kubectl command to get all CRDs
	cmd := exec.Command("kubectl", "get", "crds")
	output, err := Run(cmd)
	if err != nil {
		return false
	}

	// Check if any of the Cert Manager CRDs are present
	crdList := GetNonEmptyLines(output)
	for _, crd := range certManagerCRDs {
		for _, line := range crdList {
			if strings.Contains(line, crd) {
				return true
			}
		}
	}

	return false
}

// LoadImageToKindClusterWithName loads a local container image to the kind cluster.
// It detects whether podman or docker is being used and uses the appropriate method.
// For podman, it saves the image to an archive and loads it via kind load image-archive.
// For docker, it uses kind load docker-image directly.
func LoadImageToKindClusterWithName(name string) error {
	cluster := defaultKindCluster
	if v, ok := os.LookupEnv("KIND_CLUSTER"); ok {
		cluster = v
	}
	kindBinary := defaultKindBinary
	if v, ok := os.LookupEnv("KIND"); ok {
		kindBinary = v
	}

	// Check if using podman by looking for KIND_EXPERIMENTAL_PROVIDER or CONTAINER_TOOL
	usePodman := os.Getenv("KIND_EXPERIMENTAL_PROVIDER") == "podman" ||
		os.Getenv("CONTAINER_TOOL") == "podman"

	if usePodman {
		// For podman, save image to archive and load via kind load image-archive
		archivePath := fmt.Sprintf("/tmp/kind-image-%d.tar", os.Getpid())
		defer func() { _ = os.Remove(archivePath) }()

		// Save image using podman
		saveCmd := exec.Command("podman", "save", name, "-o", archivePath)
		if _, err := Run(saveCmd); err != nil {
			return fmt.Errorf("failed to save image with podman: %w", err)
		}

		// Load archive into Kind
		loadCmd := exec.Command(kindBinary, "load", "image-archive", archivePath, "--name", cluster)
		_, err := Run(loadCmd)
		return err
	}

	// Default: use docker-image loading
	kindOptions := []string{"load", "docker-image", name, "--name", cluster}
	cmd := exec.Command(kindBinary, kindOptions...)
	_, err := Run(cmd)
	return err
}

// GetNonEmptyLines converts given command output string into individual objects
// according to line breakers, and ignores the empty elements in it.
func GetNonEmptyLines(output string) []string {
	var res []string
	elements := strings.Split(output, "\n")
	for _, element := range elements {
		if element != "" {
			res = append(res, element)
		}
	}

	return res
}

// GetProjectDir will return the directory where the project is
func GetProjectDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return wd, fmt.Errorf("failed to get current working directory: %w", err)
	}
	wd = strings.ReplaceAll(wd, "/test/e2e", "")
	return wd, nil
}

// UncommentCode searches for target in the file and remove the comment prefix
// of the target content. The target content may span multiple lines.
func UncommentCode(filename, target, prefix string) error {
	// false positive
	// nolint:gosec
	content, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file %q: %w", filename, err)
	}
	strContent := string(content)

	idx := strings.Index(strContent, target)
	if idx < 0 {
		return fmt.Errorf("unable to find the code %q to be uncomment", target)
	}

	out := new(bytes.Buffer)
	_, err = out.Write(content[:idx])
	if err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewBufferString(target))
	if !scanner.Scan() {
		return nil
	}
	for {
		if _, err = out.WriteString(strings.TrimPrefix(scanner.Text(), prefix)); err != nil {
			return fmt.Errorf("failed to write to output: %w", err)
		}
		// Avoid writing a newline in case the previous line was the last in target.
		if !scanner.Scan() {
			break
		}
		if _, err = out.WriteString("\n"); err != nil {
			return fmt.Errorf("failed to write to output: %w", err)
		}
	}

	if _, err = out.Write(content[idx+len(target):]); err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	// false positive
	// nolint:gosec
	if err = os.WriteFile(filename, out.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write file %q: %w", filename, err)
	}

	return nil
}

// GarageCRDs is the list of CRDs the operator installs. Tests wait on these
// reaching Established=True before issuing apply commands so that kubectl's
// discovery cache and the API server's storage layer agree on which kinds and
// versions exist.
var GarageCRDs = []string{
	"garageclusters.garage.rajsingh.info",
	"garagebuckets.garage.rajsingh.info",
	"garagekeys.garage.rajsingh.info",
	"garagenodes.garage.rajsingh.info",
	"garageadmintokens.garage.rajsingh.info",
	"garagereferencegrants.garage.rajsingh.info",
}

// WaitCRDsEstablished blocks until every Garage CRD reports
// `Established=True`, then forces a kubectl discovery-cache refresh so the
// next apply does not race against a stale REST mapper. Returns the kubectl
// error if any individual wait fails.
func WaitCRDsEstablished() error {
	args := make([]string, 0, 3+len(GarageCRDs))
	args = append(args, "wait", "--for=condition=Established", "--timeout=60s")
	for _, crd := range GarageCRDs {
		args = append(args, "crd/"+crd)
	}
	if _, err := Run(exec.Command("kubectl", args...)); err != nil {
		return fmt.Errorf("waiting for CRDs to be Established: %w", err)
	}
	// Refresh kubectl's discovery cache. Without this, the very first apply
	// after `make install` can fail with "no matches for kind" because the
	// per-user discovery cache TTL has not elapsed.
	if _, err := Run(exec.Command("kubectl", "api-resources", "--request-timeout=10s")); err != nil {
		// Non-fatal — apply Eventually loops will retry if discovery is stale.
		_, _ = fmt.Fprintf(GinkgoWriter, "warning: kubectl api-resources refresh failed: %v\n", err)
	}
	return nil
}
