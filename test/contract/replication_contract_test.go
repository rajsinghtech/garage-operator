//go:build garagecontract

package contract

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	"github.com/rajsinghtech/garage-operator/internal/controller"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// The replication contract runs the exact script and environment of a
// GarageReplication Job (controller.RenderReplicationJob) in the rclone image
// the operator pins, against two independent Garage clusters. It pins the
// engine behaviours the controller relies on: copy/sync semantics per mode,
// the safety guards and their exit codes, the failure classification and the
// termination-message format. The container runs like the Job's Pod: non-root
// (UID 65532), read-only root filesystem, no capabilities.
//
// It needs a container runtime (docker or podman, or
// REPLICATION_CONTRACT_RUNTIME) in addition to GARAGE_BIN, and skips without
// one unless REPLICATION_CONTRACT_REQUIRED=true (set in CI, so a missing
// runtime fails instead of silently skipping). REPLICATION_IMAGE overrides the
// image.

const (
	replSrcKeyID     = "GK0123456789abcdef0123456a"
	replSrcSecretKey = "1111111111111111111111111111111111111111111111111111111111111111"
	replDstKeyID     = "GKfedcba9876543210fedcba9b"
	replDstSecretKey = "2222222222222222222222222222222222222222222222222222222222222222"

	replContainerWorkDir = "/tmp/garage-replication"
	replContainerOutDir  = "/out"
)

func replicationImage() string {
	if image := os.Getenv("REPLICATION_IMAGE"); image != "" {
		return image
	}
	return controller.DefaultReplicationImage
}

// containerRuntime returns the docker or podman binary that runs the rclone
// image.
func containerRuntime(t *testing.T) string {
	t.Helper()
	candidates := []string{"docker", "podman"}
	if rt := os.Getenv("REPLICATION_CONTRACT_RUNTIME"); rt != "" {
		candidates = []string{rt}
	}
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			return path
		}
	}
	if os.Getenv("REPLICATION_CONTRACT_REQUIRED") == "true" {
		t.Fatalf("no container runtime (%v) to run %s", candidates, replicationImage())
	}
	t.Skipf("no container runtime (%v); set REPLICATION_CONTRACT_REQUIRED=true to fail instead", candidates)
	return ""
}

type replCluster struct {
	nd     *node
	keyID  string
	secret string
}

// replicationCluster starts a single-node Garage with one imported key that
// has read+write on the given buckets.
func replicationCluster(t *testing.T, keyID, secret string, buckets ...string) *replCluster {
	t.Helper()
	nd := readyNode(t)
	ctx := context.Background()
	if _, err := nd.client.ImportKey(ctx, garage.ImportKeyRequest{AccessKeyID: keyID, SecretAccessKey: secret, Name: "replication"}); err != nil {
		t.Fatal(err)
	}
	c := &replCluster{nd: nd, keyID: keyID, secret: secret}
	for _, b := range buckets {
		c.bucket(t, b)
	}
	return c
}

func (c *replCluster) bucket(t *testing.T, name string) {
	t.Helper()
	ctx := context.Background()
	b, err := c.nd.client.CreateBucket(ctx, garage.CreateBucketRequest{GlobalAlias: name})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.nd.client.AllowBucketKey(ctx, garage.AllowBucketKeyRequest{
		BucketID: b.ID, AccessKeyID: c.keyID, Permissions: garage.BucketKeyPerms{Read: true, Write: true},
	}); err != nil {
		t.Fatal(err)
	}
}

func (c *replCluster) url() string { return "http://" + c.nd.s3Addr }

// rclone runs rclone from the image against the cluster as remote "c" for
// test setup and assertions.
func (c *replCluster) rclone(t *testing.T, stdin []byte, args ...string) string {
	t.Helper()
	runArgs := []string{"run", "--rm", "--network", "host"}
	if stdin != nil {
		runArgs = append(runArgs, "-i")
	}
	for _, e := range []string{
		"RCLONE_CONFIG_C_TYPE=s3", "RCLONE_CONFIG_C_PROVIDER=Other",
		"RCLONE_CONFIG_C_ENDPOINT=" + c.url(), "RCLONE_CONFIG_C_REGION=garage",
		"RCLONE_CONFIG_C_FORCE_PATH_STYLE=true", "RCLONE_CONFIG_C_NO_CHECK_BUCKET=true",
		"RCLONE_CONFIG_C_ACCESS_KEY_ID=" + c.keyID, "RCLONE_CONFIG_C_SECRET_ACCESS_KEY=" + c.secret,
	} {
		runArgs = append(runArgs, "-e", e)
	}
	runArgs = append(runArgs, replicationImage())
	runArgs = append(runArgs, args...)
	cmd := exec.Command(containerRuntime(t), runArgs...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("rclone %v: %v\n%s", args, err, stderr.String())
	}
	return string(out)
}

func (c *replCluster) put(t *testing.T, bucket, key, body string) {
	t.Helper()
	c.rclone(t, []byte(body), "rcat", "c:"+bucket+"/"+key)
}

func (c *replCluster) del(t *testing.T, bucket, key string) {
	t.Helper()
	c.rclone(t, nil, "deletefile", "c:"+bucket+"/"+key)
}

func (c *replCluster) cat(t *testing.T, bucket, key string) string {
	t.Helper()
	return c.rclone(t, nil, "cat", "c:"+bucket+"/"+key)
}

func (c *replCluster) list(t *testing.T, bucket string) []string {
	t.Helper()
	out := strings.Fields(c.rclone(t, nil, "lsf", "-R", "--files-only", "c:"+bucket))
	sort.Strings(out)
	return out
}

type replRun struct {
	exit   int
	fields map[string]string
	output string
}

// writableDir creates a host directory the container's non-root user can
// write. What that user writes there (mode 0600, umask 077) is read and
// removed through takeTerminationLog, as root inside a container.
func writableDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	return dir
}

// takeTerminationLog returns the termination log the Job container wrote in
// dir, reading it as root in a container (the kubelet reads it as root too),
// and empties dir so the test's cleanup can remove it.
func takeTerminationLog(t *testing.T, dir string) []byte {
	t.Helper()
	cmd := exec.Command(containerRuntime(t), "run", "--rm", "--user", "0", "--network", "none",
		"-v", dir+":"+replContainerOutDir, "--entrypoint", "/bin/sh", replicationImage(),
		"-c", "cat "+replContainerOutDir+"/termination-log 2>/dev/null; rm -rf "+replContainerOutDir+"/*")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	msg, err := cmd.Output()
	if err != nil {
		t.Fatalf("reading the termination log: %v\n%s", err, stderr.String())
	}
	return msg
}

// runReplication renders the Job for one bucket and runs its container the
// way the kubelet would: same image, command and environment (secretKeyRef
// values resolved from the test Secrets), same user and read-only root
// filesystem, an emptyDir-like work directory and a termination log.
func runReplication(t *testing.T, src, dst *replCluster, mutate func(*garagev1beta1.GarageReplication), bucket garagev1beta1.ReplicationBucket, signalAfter time.Duration, extraEnv ...string) replRun {
	t.Helper()
	repl := &garagev1beta1.GarageReplication{
		ObjectMeta: metav1.ObjectMeta{Name: "contract", Namespace: "default", UID: "uid"},
		Spec: garagev1beta1.GarageReplicationSpec{
			Source:      garagev1beta1.ReplicationEndpoint{CredentialsSecretRef: garagev1beta1.ReplicationCredentialsRef{Name: "src"}},
			Destination: garagev1beta1.ReplicationEndpoint{CredentialsSecretRef: garagev1beta1.ReplicationCredentialsRef{Name: "dst"}},
			Buckets:     []garagev1beta1.ReplicationBucket{bucket},
		},
	}
	if mutate != nil {
		mutate(repl)
	}
	secrets := map[string]map[string]string{
		"src": {"access-key-id": src.keyID, "secret-access-key": src.secret},
		"dst": {"access-key-id": dst.keyID, "secret-access-key": dst.secret},
	}
	job := controller.RenderReplicationJob(repl, bucket, time.Now().UTC(), replicationImage(), src.url(), "garage", dst.url(), "garage")
	pod := job.Spec.Template.Spec
	container := pod.Containers[0]
	if container.Command[0] != "/bin/sh" || *pod.SecurityContext.RunAsUser != 65532 || !*container.SecurityContext.ReadOnlyRootFilesystem {
		t.Fatalf("the Job shape changed; update this harness: %+v", container)
	}

	out := writableDir(t)
	args := make([]string, 0, 32+2*len(container.Env)+2*len(extraEnv))
	args = append(args,
		"run", "--rm", "--network", "host",
		"--user", fmt.Sprintf("%d:%d", *pod.SecurityContext.RunAsUser, *pod.SecurityContext.RunAsGroup),
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		// The Job's work directory is an emptyDir.
		"--tmpfs", replContainerWorkDir+":rw,mode=1777",
		"-v", out+":"+replContainerOutDir,
		"-e", "GR_TERMINATION_LOG="+replContainerOutDir+"/termination-log",
		"--entrypoint", container.Command[0],
	)
	for _, e := range container.Env {
		value := e.Value
		if e.ValueFrom != nil {
			ref := e.ValueFrom.SecretKeyRef
			value = secrets[ref.Name][ref.Key]
		}
		args = append(args, "-e", e.Name+"="+value)
	}
	for _, e := range extraEnv {
		args = append(args, "-e", e)
	}
	args = append(args, container.Image)
	args = append(args, container.Command[1:]...)

	cmd := exec.Command(containerRuntime(t), args...)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if signalAfter > 0 {
		// The runtime CLI proxies the signal to the container, like the
		// kubelet stopping the Pod.
		time.AfterFunc(signalAfter, func() { _ = cmd.Process.Signal(syscall.SIGTERM) })
	}
	err := cmd.Wait()
	run := replRun{output: output.String(), fields: map[string]string{}}
	if exitErr, ok := err.(*exec.ExitError); ok {
		run.exit = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	msg := takeTerminationLog(t, out)
	if len(msg) == 0 {
		t.Fatalf("no termination message (exit %d):\n%s", run.exit, run.output)
	}
	for _, f := range strings.Fields(string(msg)) {
		if k, v, ok := strings.Cut(f, "="); ok {
			run.fields[k] = v
		}
	}
	if !strings.HasPrefix(string(msg), "garage-replication/v1 ") {
		t.Fatalf("termination message %q", msg)
	}
	if len(msg) > 4096 {
		t.Fatalf("termination message is %d bytes; the kubelet keeps 4096", len(msg))
	}
	return run
}

func (r replRun) want(t *testing.T, exit int, kv ...string) {
	t.Helper()
	if r.exit != exit {
		t.Fatalf("exit %d, want %d; termination %v\n%s", r.exit, exit, r.fields, r.output)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if r.fields[kv[i]] != kv[i+1] {
			t.Fatalf("%s=%q, want %q; termination %v\n%s", kv[i], r.fields[kv[i]], kv[i+1], r.fields, r.output)
		}
	}
}

func (r replRun) wantFailure(t *testing.T, reason garagev1beta1.ReplicationFailureReason) {
	t.Helper()
	if r.exit == 0 || r.fields["reason"] != string(reason) {
		t.Fatalf("want a failure with reason %s, got exit %d %v\n%s", reason, r.exit, r.fields, r.output)
	}
}

func equalLists(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
}

func TestContract_ReplicationModesGuardsAndReasons(t *testing.T) {
	containerRuntime(t)
	src := replicationCluster(t, replSrcKeyID, replSrcSecretKey, "medias", "photos", "empty", "sized")
	dst := replicationCluster(t, replDstKeyID, replDstSecretKey, "medias", "photos-dr", "guarded", "sized")
	medias := garagev1beta1.ReplicationBucket{Source: "medias", Destination: "medias"}
	copyMode := func(r *garagev1beta1.GarageReplication) { r.Spec.Mode = garagev1beta1.ReplicationModeCopy }
	mirror := func(maxDeletes int64, maxDeleteSize string) func(*garagev1beta1.GarageReplication) {
		return func(r *garagev1beta1.GarageReplication) {
			r.Spec.Mode = garagev1beta1.ReplicationModeMirror
			r.Spec.Mirror = &garagev1beta1.ReplicationMirrorConfig{MaxDeletes: maxDeletes, MaxDeleteSize: maxDeleteSize}
		}
	}

	src.put(t, "medias", "a.txt", "alpha")
	src.put(t, "medias", "b.txt", "bravo")
	src.put(t, "medias", "dir/c.txt", "charlie")

	t.Run("initial full sync", func(t *testing.T) {
		runReplication(t, src, dst, copyMode, medias, 0).want(t, 0, "stats", "1", "transfers", "3", "bytes", "17", "reason", "")
		equalLists(t, "destination", dst.list(t, "medias"), "a.txt", "b.txt", "dir/c.txt")
	})

	t.Run("incremental sync copies only changes", func(t *testing.T) {
		src.put(t, "medias", "a.txt", "alpha-v2")
		src.put(t, "medias", "d.txt", "delta")
		runReplication(t, src, dst, copyMode, medias, 0).want(t, 0, "transfers", "2", "checks", "3")
		if got := dst.cat(t, "medias", "a.txt"); got != "alpha-v2" {
			t.Fatalf("a.txt = %q", got)
		}
	})

	t.Run("copy keeps source deletions on the destination", func(t *testing.T) {
		src.del(t, "medias", "b.txt")
		runReplication(t, src, dst, copyMode, medias, 0).want(t, 0, "transfers", "0", "deletes", "0")
		equalLists(t, "destination", dst.list(t, "medias"), "a.txt", "b.txt", "d.txt", "dir/c.txt")
	})

	t.Run("verification passes on an up-to-date destination", func(t *testing.T) {
		runReplication(t, src, dst, func(r *garagev1beta1.GarageReplication) {
			copyMode(r)
			r.Spec.Verification = garagev1beta1.ReplicationVerificationCheck
		}, medias, 0).want(t, 0, "verify", "Passed", "differences", "0")
	})

	t.Run("mirror propagates deletions", func(t *testing.T) {
		runReplication(t, src, dst, mirror(10, ""), medias, 0).want(t, 0, "deletes", "1")
		equalLists(t, "destination", dst.list(t, "medias"), "a.txt", "d.txt", "dir/c.txt")
	})

	t.Run("mirror stops at maxDeletes with the no-retry exit code", func(t *testing.T) {
		src.del(t, "medias", "a.txt")
		src.del(t, "medias", "d.txt")
		run := runReplication(t, src, dst, mirror(1, ""), medias, 0)
		run.want(t, 65, "reason", string(garagev1beta1.ReplicationFailureMaxDeletesExceeded))
		if left := len(dst.list(t, "medias")); left != 2 {
			t.Fatalf("one deletion allowed, %d objects left (want 2)", left)
		}
	})

	t.Run("mirror stops at maxDeleteSize with the no-retry exit code", func(t *testing.T) {
		src.put(t, "sized", "keep.txt", "k")
		for _, key := range []string{"big-1.bin", "big-2.bin"} {
			dst.put(t, "sized", key, strings.Repeat("x", 2048))
		}
		dst.put(t, "sized", "keep.txt", "k")
		// 1K: deleting both 2 KiB objects would exceed it.
		run := runReplication(t, src, dst, mirror(1000, "1K"), garagev1beta1.ReplicationBucket{Source: "sized", Destination: "sized"}, 0)
		run.want(t, 65, "reason", string(garagev1beta1.ReplicationFailureMaxDeletesExceeded))
		if left := dst.list(t, "sized"); len(left) < 2 {
			t.Fatalf("maxDeleteSize must stop the deletions, left %v", left)
		}
	})

	t.Run("empty source never wipes a non-empty destination", func(t *testing.T) {
		dst.put(t, "guarded", "keep.txt", "precious")
		run := runReplication(t, src, dst, mirror(1000, ""), garagev1beta1.ReplicationBucket{Source: "empty", Destination: "guarded"}, 0)
		run.want(t, 64, "reason", string(garagev1beta1.ReplicationFailureSourceEmpty), "stats", "0")
		equalLists(t, "guarded destination", dst.list(t, "guarded"), "keep.txt")
	})

	t.Run("content type and user metadata are copied", func(t *testing.T) {
		src.rclone(t, []byte("png"), "rcat", "--header-upload", "Content-Type: image/png",
			"--header-upload", "Cache-Control: max-age=60", "-M", "--metadata-set", "owner=team-a", "c:photos/meta.png")
		runReplication(t, src, dst, copyMode, garagev1beta1.ReplicationBucket{Source: "photos", Destination: "photos-dr"}, 0).want(t, 0, "errors", "0")
		out := dst.rclone(t, nil, "lsjson", "-M", "c:photos-dr/meta.png")
		for _, want := range []string{`"content-type":"image/png"`, `"cache-control":"max-age=60"`, `"owner":"team-a"`, `"mtime":`} {
			if !strings.Contains(strings.ReplaceAll(out, " ", ""), want) {
				t.Fatalf("destination metadata lacks %s:\n%s", want, out)
			}
		}
		dst.del(t, "photos-dr", "meta.png")
		src.del(t, "photos", "meta.png")
	})

	t.Run("renamed destination bucket", func(t *testing.T) {
		src.put(t, "photos", "p.jpg", "jpeg")
		runReplication(t, src, dst, copyMode, garagev1beta1.ReplicationBucket{Source: "photos", Destination: "photos-dr"}, 0).want(t, 0, "transfers", "1")
		equalLists(t, "photos-dr", dst.list(t, "photos-dr"), "p.jpg")
	})

	t.Run("bad credentials are AuthFailed", func(t *testing.T) {
		bad := *src
		bad.secret = strings.Repeat("0", 64)
		run := runReplication(t, &bad, dst, copyMode, medias, 0)
		run.wantFailure(t, garagev1beta1.ReplicationFailureAuthFailed)
		if strings.Contains(run.output, bad.secret) || strings.Contains(run.output, dst.secret) {
			t.Fatal("secret material in the Job output")
		}
	})

	t.Run("missing source bucket is BucketNotFound (rclone exit 3)", func(t *testing.T) {
		runReplication(t, src, dst, copyMode, garagev1beta1.ReplicationBucket{Source: "nope", Destination: "medias"}, 0).
			want(t, 3, "reason", string(garagev1beta1.ReplicationFailureBucketNotFound))
	})

	t.Run("missing destination bucket is BucketNotFound", func(t *testing.T) {
		runReplication(t, src, dst, copyMode, garagev1beta1.ReplicationBucket{Source: "medias", Destination: "nope"}, 0).
			wantFailure(t, garagev1beta1.ReplicationFailureBucketNotFound)
	})

	t.Run("unreachable endpoint is EndpointUnreachable (rclone exit 5)", func(t *testing.T) {
		gone := *dst
		gone.nd = &node{s3Addr: fmt.Sprintf("127.0.0.1:%d", freePort(t))}
		// rclone's default retries (3 runs x 10 low-level retries with
		// backoff) take minutes against a closed port; rclone reads these
		// overrides from the environment because the Job does not pin them.
		run := runReplication(t, src, &gone, copyMode, medias, 0,
			"RCLONE_RETRIES=1", "RCLONE_LOW_LEVEL_RETRIES=1", "RCLONE_CONTIMEOUT=2s")
		run.want(t, 5, "reason", string(garagev1beta1.ReplicationFailureEndpointUnreachable))
	})

	t.Run("SIGTERM stops the copy and still reports", func(t *testing.T) {
		big := bytes.Repeat([]byte("x"), 4<<20)
		src.rclone(t, big, "rcat", "c:medias/big.bin")
		run := runReplication(t, src, dst, func(r *garagev1beta1.GarageReplication) {
			copyMode(r)
			r.Spec.Transfer = &garagev1beta1.ReplicationTransferConfig{BandwidthLimit: "200K"}
		}, medias, 5*time.Second)
		run.want(t, 143, "reason", "Terminated")
		for _, key := range dst.list(t, "medias") {
			if key == "big.bin" {
				t.Fatal("an interrupted upload must not leave a partial object")
			}
		}
	})
}
