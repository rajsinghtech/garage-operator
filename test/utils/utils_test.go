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
	"bytes"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPinCertManagerImages(t *testing.T) {
	var manifest strings.Builder
	for source := range certmanagerImagePins {
		if strings.Contains(source, "acmesolver") {
			_, _ = fmt.Fprintf(&manifest, "      - --acme-http01-solver-image=%s\n", source)
		} else {
			_, _ = fmt.Fprintf(&manifest, "      image: %q\n", source)
		}
	}

	pinned, err := pinCertManagerImages([]byte(manifest.String()))
	if err != nil {
		t.Fatalf("pin cert-manager images: %v", err)
	}
	for source, target := range certmanagerImagePins {
		if strings.Contains(string(pinned), `"`+source+`"`) {
			t.Errorf("unpinned image remains: %s", source)
		}
		if !strings.Contains(string(pinned), target) {
			t.Errorf("pinned image is absent: %s", target)
		}
	}
}

func TestPinCertManagerImagesFailsClosed(t *testing.T) {
	if _, err := pinCertManagerImages([]byte("image: example.invalid/new:latest\n")); err == nil {
		t.Fatal("expected an error when required cert-manager images are absent")
	}

	var manifest strings.Builder
	for source := range certmanagerImagePins {
		if strings.Contains(source, "acmesolver") {
			_, _ = fmt.Fprintf(&manifest, "- --acme-http01-solver-image=%s\n", source)
		} else {
			_, _ = fmt.Fprintf(&manifest, "image: %s\n", source)
		}
	}
	for _, unpinned := range []string{
		"image: example.invalid/new:latest\n",
		"- --new-helper-image=example.invalid/new:latest\n",
	} {
		if _, err := pinCertManagerImages([]byte(manifest.String() + unpinned)); err == nil ||
			!strings.Contains(err.Error(), "image without digest") {
			t.Errorf("expected unpinned transitive image error for %q, got %v", unpinned, err)
		}
	}
}

// An unbounded `kubectl delete` in a teardown hook blocks on Garage's
// fail-closed finalizers and burns the rest of the shard's `go test` budget, so
// the suite reports "test timed out" against an arbitrary cleanup line instead of
// the stuck finalizer. Deletes therefore carry a deadline by default — but only
// deletes, and only when the caller did not state one.
func TestBoundKubectlDelete(t *testing.T) {
	wantDeleteTimeout := "--timeout=" + defaultKubectlDeleteTimeout
	for _, tc := range []struct {
		name                string
		args                []string
		bound               bool
		wantRequestTimeout  string
		requestTimeoutAdded bool
	}{
		{"bare delete", []string{kubectlBinary, kubectlDeleteVerb, "garagecluster", "c", "-n", "ns"}, true, defaultKubectlRequestTimeout, true},
		{"delete with flags before the verb", []string{kubectlBinary, "--context=kind", kubectlDeleteVerb, "ns", "x"}, true, defaultKubectlRequestTimeout, true},
		{"delete all", []string{kubectlBinary, kubectlDeleteVerb, "garagecluster", "--all", "-n", "ns", "--ignore-not-found"}, true, defaultKubectlRequestTimeout, true},
		{"explicit timeout is preserved", []string{kubectlBinary, kubectlDeleteVerb, "ns", "x", "--timeout=90s"}, false, defaultKubectlRequestTimeout, true},
		{"non-blocking delete gets request deadline", []string{kubectlBinary, kubectlDeleteVerb, "-f", "u", "--wait=false"}, false, defaultKubectlRequestTimeout, true},
		{"explicit request timeout is preserved", []string{kubectlBinary, kubectlDeleteVerb, "ns", "x", "--wait=false", "--request-timeout=90s"}, false, "90s", false},
		{"other verbs untouched", []string{kubectlBinary, "wait", "--for=delete", "pod/x"}, false, "", false},
		{"delete only as a value is not the verb", []string{kubectlBinary, "get", "deployments", "-l", "delete"}, false, "", false},
		{"not kubectl", []string{"make", kubectlDeleteVerb}, false, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(tc.args[0], tc.args[1:]...) // #nosec G204 -- fixed test inputs
			before := strings.Join(cmd.Args, " ")
			boundKubectlDelete(cmd)
			after := strings.Join(cmd.Args, " ")

			changed := after != before
			wantChanged := tc.bound || tc.requestTimeoutAdded
			if changed != wantChanged {
				t.Fatalf("changed=%t want %t (%q -> %q)", changed, wantChanged, before, after)
			}
			if tc.bound && !strings.Contains(after, wantDeleteTimeout) {
				t.Fatalf("want %q added, got %q", wantDeleteTimeout, after)
			}
			if tc.wantRequestTimeout != "" && !strings.Contains(after, "--request-timeout="+tc.wantRequestTimeout) {
				t.Fatalf("want request timeout %q, got %q", tc.wantRequestTimeout, after)
			}
			if !tc.bound && strings.Count(after, "--timeout=") > strings.Count(before, "--timeout=") {
				t.Fatalf("must not add an object-wait deadline to %q, got %q", before, after)
			}
			if tc.wantRequestTimeout == "" && strings.Count(after, "--request-timeout=") > strings.Count(before, "--request-timeout=") {
				t.Fatalf("must not add an API request deadline to %q, got %q", before, after)
			}
		})
	}
}

func TestBindKubectlContext(t *testing.T) {
	t.Setenv("KIND_CLUSTER", "garage-e2e")

	cmd := exec.Command(kubectlBinary, "get", "pods")
	if err := bindKubectlContext(cmd); err != nil {
		t.Fatal(err)
	}
	if got, want := cmd.Args, []string{kubectlBinary, "--context=kind-garage-e2e", "get", "pods"}; !slices.Equal(got, want) {
		t.Fatalf("args = %v, want %v", got, want)
	}

	matching := exec.Command(kubectlBinary, "--context", "kind-garage-e2e", "get", "pods")
	if err := bindKubectlContext(matching); err != nil {
		t.Fatalf("matching context rejected: %v", err)
	}

	foreign := exec.Command(kubectlBinary, "--context=production", "get", "pods")
	if err := bindKubectlContext(foreign); err == nil {
		t.Fatal("foreign kubectl context was accepted during Kind E2E")
	}

	childContext := exec.Command(kubectlBinary, "exec", "pod/x", "--", "tool", "--context=production")
	if err := bindKubectlContext(childContext); err != nil {
		t.Fatalf("child command context was treated as kubectl context: %v", err)
	}
	if got, want := childContext.Args[1], "--context=kind-garage-e2e"; got != want {
		t.Fatalf("child command context args = %v, want %q before the exec command", childContext.Args, want)
	}
}

func TestE2ECommandTimeout(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want time.Duration
	}{
		{"docker exec", []string{"docker", "exec", "kind-node", "sh"}, defaultDockerExecTimeout},
		{"docker build", []string{"docker", "build", "."}, defaultDockerBuildTimeout},
		{"kind query", []string{"kind", "get", "clusters"}, defaultKindQueryTimeout},
		{"kind create", []string{"kind", "create", "cluster"}, defaultKindOperationTimeout},
		{"helm install", []string{"helm", "install", "garage-operator"}, defaultHelmInstallTimeout},
		{"helm uninstall", []string{"helm", "uninstall", "garage-operator"}, defaultHelmUninstallTimeout},
		{"kubectl request", []string{"kubectl", "get", "pods"}, defaultKubectlExecutionTimeout},
		{"kubectl port-forward", []string{"kubectl", "port-forward", "service/garage", "0:3900"}, 0},
		{"webhook wait uses explicit timeout", []string{"hack/wait-for-operator-webhook.sh", "kind-e2e", "webhook", "ns", "17"}, 17 * time.Second},
		{"ordinary command", []string{"printf", "ok"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := e2eCommandTimeout(exec.Command(tc.args[0], tc.args[1:]...)); got != tc.want {
				t.Fatalf("timeout = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRunE2ECommandWithTimeoutPreservesOutputWriters(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("sh", "-c", "printf stdout; printf stderr >&2") // #nosec G204 -- fixed test command
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	output, err := runE2ECommandWithTimeout(cmd, time.Second)
	if err != nil {
		t.Fatalf("run command: %v", err)
	}
	if got, want := stdout.String(), "stdout"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if got, want := stderr.String(), "stderr"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
	if !strings.Contains(string(output), "stdout") || !strings.Contains(string(output), "stderr") {
		t.Fatalf("captured output = %q, want both stdout and stderr", output)
	}
}

// A second pass must not stack deadlines: Run bounds the command it is given, and
// a caller may hand the same *exec.Cmd to a retry.
func TestBoundKubectlDeleteIsIdempotent(t *testing.T) {
	cmd := exec.Command(kubectlBinary, kubectlDeleteVerb, "garagecluster", "c", "-n", "ns")
	boundKubectlDelete(cmd)
	once := strings.Join(cmd.Args, " ")
	boundKubectlDelete(cmd)
	if twice := strings.Join(cmd.Args, " "); twice != once {
		t.Fatalf("second pass changed the command: %q -> %q", once, twice)
	}
}

func TestBoundKubectlRequest(t *testing.T) {
	wantRequestTimeout := "--request-timeout=" + defaultKubectlRequestTimeout
	for _, tc := range []struct {
		name     string
		args     []string
		changed  bool
		contains string
	}{
		{"get", []string{kubectlBinary, "get", "pods"}, true, wantRequestTimeout},
		{"global flags before verb", []string{kubectlBinary, "--context", "kind-e2e", "-n", "test", "get", "pods"}, true, wantRequestTimeout},
		{"explicit request timeout is preserved", []string{kubectlBinary, "get", "pods", "--request-timeout=90s"}, false, ""},
		{"wait stream is untouched", []string{kubectlBinary, "wait", "--for=condition=Ready", "pod/x", "--timeout=2m"}, false, ""},
		{"logs gets bounded startup and API waits", []string{kubectlBinary, "logs", "pod/x"}, true, "--pod-running-timeout=15s"},
		{"explicit logs startup wait still gets API deadline", []string{kubectlBinary, "logs", "pod/x", "--pod-running-timeout=90s"}, true, "--pod-running-timeout=90s"},
		{"following logs keep their stream open", []string{kubectlBinary, "logs", "pod/x", "--follow"}, true, "--pod-running-timeout=15s"},
		{"exec gets API deadline before child command", []string{kubectlBinary, "exec", "pod/x", "--", "get", "pods"}, true, wantRequestTimeout},
		{"child request flag cannot suppress exec API deadline", []string{kubectlBinary, "exec", "pod/x", "--", "tool", "--request-timeout=90s"}, true, wantRequestTimeout},
		{"rollout stream is untouched", []string{kubectlBinary, "rollout", "status", "deployment/x"}, false, ""},
		{"port-forward stream is untouched", []string{kubectlBinary, "port-forward", "service/x", "0:443"}, false, ""},
		{"run inserts before child command", []string{kubectlBinary, "run", "probe", "--restart=Never", "--", "sleep", "300"}, true, wantRequestTimeout},
		{"non-kubectl command is untouched", []string{"make", "get"}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(tc.args[0], tc.args[1:]...) // #nosec G204 -- fixed test inputs
			before := strings.Join(cmd.Args, " ")
			boundKubectlRequest(cmd)
			after := strings.Join(cmd.Args, " ")
			if (after != before) != tc.changed {
				t.Fatalf("changed=%t want %t (%q -> %q)", after != before, tc.changed, before, after)
			}
			if tc.contains != "" && !strings.Contains(after, tc.contains) {
				t.Fatalf("want %q in %q", tc.contains, after)
			}
			if tc.name == "run inserts before child command" {
				wantArgs := []string{kubectlBinary, "run", "probe", "--restart=Never", wantRequestTimeout, "--", "sleep", "300"}
				if !slices.Equal(cmd.Args, wantArgs) {
					t.Fatalf("args = %v, want %v", cmd.Args, wantArgs)
				}
			}
			if tc.name == "exec gets API deadline before child command" {
				wantArgs := []string{kubectlBinary, "exec", "pod/x", wantRequestTimeout, "--", "get", "pods"}
				if !slices.Equal(cmd.Args, wantArgs) {
					t.Fatalf("args = %v, want %v", cmd.Args, wantArgs)
				}
			}
		})
	}
}

func TestBoundKubectlRequestIsIdempotent(t *testing.T) {
	cmd := exec.Command(kubectlBinary, "get", "pods")
	boundKubectlRequest(cmd)
	once := strings.Join(cmd.Args, " ")
	boundKubectlRequest(cmd)
	if twice := strings.Join(cmd.Args, " "); twice != once {
		t.Fatalf("second pass changed the command: %q -> %q", once, twice)
	}
}

func TestBoundKubectlLogsRequestDeadline(t *testing.T) {
	wantRequestTimeout := "--request-timeout=" + defaultKubectlRequestTimeout
	logs := exec.Command(kubectlBinary, "logs", "pod/x")
	boundKubectlRequest(logs)
	if strings.Count(strings.Join(logs.Args, " "), wantRequestTimeout) != 1 {
		t.Fatalf("non-following logs args = %v, want one API request deadline", logs.Args)
	}

	following := exec.Command(kubectlBinary, "logs", "pod/x", "--follow")
	boundKubectlRequest(following)
	if strings.Contains(strings.Join(following.Args, " "), wantRequestTimeout) {
		t.Fatalf("following logs args = %v, must not receive a request deadline", following.Args)
	}
}
