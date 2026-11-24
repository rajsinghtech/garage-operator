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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
)

// DefaultReplicationImage is the rclone image used by GarageReplication Jobs
// unless --replication-image overrides it. Pinned by digest; Renovate bumps it.
const DefaultReplicationImage = "docker.io/rclone/rclone:1.75.2@sha256:2687085f718d3c628f7fdfb77c52a1d344332aed543110bb88088f2c70d43eb5"

const (
	replicationContainerName = "rclone"
	replicationAppName       = "garage-replication"
	replicationWorkDir       = "/tmp/garage-replication"
	replicationCAMountDir    = "/etc/garage-replication/ca"
	replicationCAFileName    = "ca.crt"
	// replicationRunAsUser is a non-root UID; the rclone image does not need
	// any file it owns and writes only to the emptyDir work directory.
	replicationRunAsUser = int64(65532)

	labelReplicationUID = "garage.rajsingh.info/replication-uid"
	labelReplicationRun = "garage.rajsingh.info/replication-run"

	annotationReplicationSource      = "garage.rajsingh.info/replication-source-bucket"
	annotationReplicationDestination = "garage.rajsingh.info/replication-destination-bucket"
	annotationReplicationRunID       = "garage.rajsingh.info/replication-run-id"
	annotationReplicationSpecHash    = "garage.rajsingh.info/replication-spec-hash"
	annotationReplicationMode        = "garage.rajsingh.info/replication-mode"

	// Exit codes of the replication script for failures a retry must not
	// repeat. The Job's podFailurePolicy fails the Job on them immediately.
	replicationExitSourceEmpty = 64
	replicationExitMaxDeletes  = 65

	// rcloneTrue is a boolean rclone option value.
	rcloneTrue = "true"
)

// replicationScript drives one bucket's replication inside the Job. It runs
// in the rclone image (busybox sh), never receives credentials as arguments
// (rclone reads them from RCLONE_CONFIG_* environment variables populated
// from Secrets), and writes a single bounded key=value line to the
// termination log for the operator: exit code, fixed failure reason,
// verification result and rclone's counters. Engine output, which can name
// objects, stays in the Pod log.
//
// Failures are classified by rclone's exit code first: 3 and 4 (directory or
// file not found), 5 (retryable errors left after the retries: connection
// failures, timeouts, 5xx) and, in Mirror mode, 7 (fatal error, which with
// the flags used here only --max-delete and --max-delete-size raise). Exit
// codes 1 and 6 do not tell an authentication failure from a missing
// destination bucket (a PUT answered 404 NoSuchBucket), so the log decides
// those, and anything else is TransferErrors.
const replicationScript = `set -u
umask 077
WORK="${GR_WORK_DIR:-/tmp/garage-replication}"
TERMINATION_LOG="${GR_TERMINATION_LOG:-/dev/termination-log}"
RCLONE="${GR_RCLONE:-rclone}"
mkdir -p "$WORK/cache" || exit 1
: > "$WORK/rclone.conf"
: > "$WORK/sync.log"
: > "$WORK/check.log"
export RCLONE_CONFIG="$WORK/rclone.conf" RCLONE_CACHE_DIR="$WORK/cache" HOME="$WORK" TMPDIR="$WORK"

CHILD=""
TERMINATED=0
VERIFY=""
DIFFERENCES=""
trap 'TERMINATED=1; if [ -n "$CHILD" ]; then kill -TERM "$CHILD" 2>/dev/null; fi' TERM INT

CA_ARGS=""
if [ -n "${GR_CA_FILES:-}" ]; then
  for f in /etc/ssl/certs/ca-certificates.crt $GR_CA_FILES; do
    if [ -f "$f" ]; then CA_ARGS="$CA_ARGS --ca-cert $f"; fi
  done
fi

COMMON="--use-json-log --log-level NOTICE --stats 1m --stats-log-level NOTICE --checksum --metadata --transfers $GR_TRANSFERS --checkers $GR_CHECKERS"
if [ -n "${GR_BWLIMIT:-}" ]; then COMMON="$COMMON --bwlimit $GR_BWLIMIT"; fi

SRC="src:$GR_SOURCE_BUCKET"
DST="dst:$GR_DESTINATION_BUCKET"

stat_field() {
  printf '%s' "$1" | sed -n "s/.*\"$2\":\([0-9][0-9.]*\).*/\1/p" | head -n 1
}

finish() {
  rc="$1"
  reason="$2"
  line=$(grep '"stats":' "$WORK/sync.log" 2>/dev/null | tail -n 1)
  stats="stats=0"
  if [ -n "$line" ]; then
    stats="stats=1"
    for k in transfers bytes checks deletes errors elapsedTime; do
      stats="$stats $k=$(stat_field "$line" "$k")"
    done
  fi
  printf 'garage-replication/v1 exit=%s reason=%s verify=%s differences=%s %s\n' \
    "$rc" "$reason" "$VERIFY" "$DIFFERENCES" "$stats" > "$TERMINATION_LOG" 2>/dev/null
  exit "$rc"
}

run_rclone() {
  log="$1"
  shift
  tail -n +1 -f "$log" &
  TAIL=$!
  # shellcheck disable=SC2086
  "$RCLONE" "$@" $CA_ARGS $COMMON --log-file "$log" &
  CHILD=$!
  rc=0
  wait "$CHILD" || rc=$?
  while kill -0 "$CHILD" 2>/dev/null; do
    rc=0
    wait "$CHILD" || rc=$?
  done
  CHILD=""
  sleep 1
  kill "$TAIL" 2>/dev/null
  return "$rc"
}

# classify prints the failure reason of rclone exit code $1 with log $2.
classify() {
  case "$1" in
    3|4) echo BucketNotFound; return ;;
    5) echo EndpointUnreachable; return ;;
    7) if [ "$GR_MODE" = Mirror ]; then echo MaxDeletesExceeded; return; fi ;;
  esac
  if grep -qE 'AccessDenied|InvalidAccessKeyId|SignatureDoesNotMatch|StatusCode: 403' "$2"; then echo AuthFailed
  elif grep -q 'NoSuchBucket' "$2"; then echo BucketNotFound
  elif grep -qE 'x509|certificate' "$2"; then echo EndpointUnreachable
  else echo TransferErrors
  fi
}

# listing_state prints nonempty, empty or error for a bucket. The first
# listing stops after one entry; only an apparently empty bucket is listed to
# completion so a listing error is not mistaken for an empty bucket.
listing_state() {
  # shellcheck disable=SC2086
  first=$("$RCLONE" lsf --max-depth 1 $CA_ARGS "$1" 2>/dev/null | head -n 1)
  if [ -n "$first" ]; then echo nonempty; return; fi
  # shellcheck disable=SC2086
  if out=$("$RCLONE" lsf --max-depth 1 $CA_ARGS "$1"); then
    if [ -n "$out" ]; then echo nonempty; else echo empty; fi
  else
    echo error
  fi
}

case "$GR_MODE" in
  Copy) set -- copy "$SRC" "$DST" ;;
  Mirror)
    set -- sync "$SRC" "$DST" --max-delete "$GR_MAX_DELETES"
    if [ -n "${GR_MAX_DELETE_SIZE:-}" ]; then set -- "$@" --max-delete-size "$GR_MAX_DELETE_SIZE"; fi
    ;;
  *) echo "unknown mode $GR_MODE" >&2; finish 2 Unknown ;;
esac

if [ "$GR_MODE" = Mirror ]; then
  src_state=$(listing_state "$SRC")
  case "$src_state" in
    error) echo "listing the source bucket failed" >&2; finish 3 BucketNotFound ;;
    empty)
      dst_state=$(listing_state "$DST")
      if [ "$dst_state" != empty ]; then
        echo "refusing to mirror: the source bucket is empty and the destination bucket is not (or cannot be listed)" >&2
        finish 64 SourceEmpty
      fi
      ;;
  esac
fi

rc=0
run_rclone "$WORK/sync.log" "$@" || rc=$?
if [ "$TERMINATED" = 1 ]; then finish 143 Terminated; fi
if [ "$rc" != 0 ]; then
  reason=$(classify "$rc" "$WORK/sync.log")
  if [ "$reason" = MaxDeletesExceeded ]; then finish 65 "$reason"; fi
  finish "$rc" "$reason"
fi

if [ "${GR_VERIFY:-None}" = Check ]; then
  if [ "$GR_MODE" = Copy ]; then set -- check "$SRC" "$DST" --one-way; else set -- check "$SRC" "$DST"; fi
  crc=0
  run_rclone "$WORK/check.log" "$@" || crc=$?
  if [ "$TERMINATED" = 1 ]; then finish 143 Terminated; fi
  DIFFERENCES=$(sed -n 's/.*"msg":"\([0-9][0-9]*\) differences found".*/\1/p' "$WORK/check.log" | tail -n 1)
  if [ "$crc" = 0 ]; then
    VERIFY=Passed
  else
    VERIFY=Failed
    if [ -n "$DIFFERENCES" ] && [ "$DIFFERENCES" != 0 ]; then finish 1 VerificationFailed; fi
    finish "$crc" "$(classify "$crc" "$WORK/check.log")"
  fi
fi
finish 0 ""
`

// resolvedReplicationEndpoint is one side of a replication after resolving
// clusterRef or endpoint.
type resolvedReplicationEndpoint struct {
	URL         string
	Region      string
	Credentials garagev1beta1.ReplicationCredentialsRef
	CABundle    *garagev1beta1.ReplicationCABundleRef
}

// replicationJobInput is everything a per-bucket Job depends on.
type replicationJobInput struct {
	Replication *garagev1beta1.GarageReplication
	Bucket      garagev1beta1.ReplicationBucket
	RunID       string
	SpecHash    string
	Image       string
	Source      resolvedReplicationEndpoint
	Destination resolvedReplicationEndpoint
}

// replicationRunID derives a short, sortable run identifier from the run's
// start time.
func replicationRunID(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 36)
}

// replicationJobName is deterministic for (replication, run, bucket), so a
// retried reconcile never creates a second Job for the same work.
func replicationJobName(replName, runID string, b garagev1beta1.ReplicationBucket) string {
	sum := sha256.Sum256([]byte(b.Source + "/" + b.Destination))
	prefix := replName
	if len(prefix) > 40 {
		prefix = strings.TrimRight(prefix[:40], "-.")
	}
	return fmt.Sprintf("%s-%s-%s", prefix, runID, hex.EncodeToString(sum[:])[:8])
}

// rcloneSize turns an API size ("50M", "1024") into an rclone size suffix.
// rclone reads a bare number as KiB, the API as bytes.
func rcloneSize(v string) string {
	if v == "" {
		return ""
	}
	if last := v[len(v)-1]; last >= '0' && last <= '9' {
		return v + "B"
	}
	return v
}

func replicationSelectorLabels(repl *garagev1beta1.GarageReplication) map[string]string {
	return map[string]string{
		labelAppName:        replicationAppName,
		labelAppManagedBy:   operatorName,
		labelReplicationUID: string(repl.UID),
	}
}

// buildReplicationJob renders the Job replicating one bucket for one run.
func buildReplicationJob(in replicationJobInput) *batchv1.Job {
	repl := in.Replication
	spec := &repl.Spec
	mode := garagev1beta1.EffectiveReplicationMode(spec)

	labels := replicationSelectorLabels(repl)
	labels[labelReplicationRun] = in.RunID
	if len(repl.Name) <= 63 {
		labels[labelAppInstance] = repl.Name
	}

	podLabels := map[string]string{}
	podAnnotations := map[string]string{}
	if pt := spec.PodTemplate; pt != nil {
		for k, v := range pt.Labels {
			podLabels[k] = v
		}
		for k, v := range pt.Annotations {
			podAnnotations[k] = v
		}
	}
	for k, v := range labels {
		podLabels[k] = v
	}

	transfers, checkers := int32(4), int32(8)
	bwlimit := ""
	if t := spec.Transfer; t != nil {
		if t.Concurrency > 0 {
			transfers = t.Concurrency
		}
		if t.Checkers > 0 {
			checkers = t.Checkers
		}
		bwlimit = rcloneSize(t.BandwidthLimit)
	}
	backoffLimit, deadline := int32(2), int64(21600)
	if r := spec.Retry; r != nil {
		if r.BackoffLimit != nil {
			backoffLimit = *r.BackoffLimit
		}
		if r.ActiveDeadlineSeconds != nil {
			deadline = *r.ActiveDeadlineSeconds
		}
	}
	verification := spec.Verification
	if verification == "" {
		verification = garagev1beta1.ReplicationVerificationNone
	}

	env := []corev1.EnvVar{
		{Name: "GR_MODE", Value: string(mode)},
		{Name: "GR_SOURCE_BUCKET", Value: in.Bucket.Source},
		{Name: "GR_DESTINATION_BUCKET", Value: in.Bucket.Destination},
		{Name: "GR_VERIFY", Value: string(verification)},
		{Name: "GR_TRANSFERS", Value: strconv.Itoa(int(transfers))},
		{Name: "GR_CHECKERS", Value: strconv.Itoa(int(checkers))},
		{Name: "GR_WORK_DIR", Value: replicationWorkDir},
	}
	if bwlimit != "" {
		env = append(env, corev1.EnvVar{Name: "GR_BWLIMIT", Value: bwlimit})
	}
	if mode == garagev1beta1.ReplicationModeMirror && spec.Mirror != nil {
		env = append(env, corev1.EnvVar{Name: "GR_MAX_DELETES", Value: strconv.FormatInt(spec.Mirror.MaxDeletes, 10)})
		if size := rcloneSize(spec.Mirror.MaxDeleteSize); size != "" {
			env = append(env, corev1.EnvVar{Name: "GR_MAX_DELETE_SIZE", Value: size})
		}
	}

	volumes := []corev1.Volume{{
		Name:         "work",
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
	}}
	mounts := []corev1.VolumeMount{{Name: "work", MountPath: replicationWorkDir}}
	var caFiles []string
	for _, side := range []struct {
		remote, name string
		ep           resolvedReplicationEndpoint
	}{{"SRC", "source", in.Source}, {"DST", "destination", in.Destination}} {
		env = append(env, rcloneRemoteEnv(side.remote, side.ep)...)
		ca := side.ep.CABundle
		if ca == nil {
			continue
		}
		key := ca.Key
		if key == "" {
			key = garagev1beta1.ReplicationDefaultCABundleKey
		}
		volName := "ca-" + side.name
		volumes = append(volumes, corev1.Volume{Name: volName, VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: ca.Name},
				Items:                []corev1.KeyToPath{{Key: key, Path: replicationCAFileName}},
			},
		}})
		dir := replicationCAMountDir + "/" + side.name
		mounts = append(mounts, corev1.VolumeMount{Name: volName, MountPath: dir, ReadOnly: true})
		caFiles = append(caFiles, dir+"/"+replicationCAFileName)
	}
	if len(caFiles) > 0 {
		env = append(env, corev1.EnvVar{Name: "GR_CA_FILES", Value: strings.Join(caFiles, " ")})
	}

	container := corev1.Container{
		Name:                     replicationContainerName,
		Image:                    in.Image,
		Command:                  []string{"/bin/sh", "-c", replicationScript},
		Env:                      env,
		VolumeMounts:             mounts,
		TerminationMessagePath:   corev1.TerminationMessagePathDefault,
		TerminationMessagePolicy: corev1.TerminationMessageReadFile,
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: ptr.To(false),
			ReadOnlyRootFilesystem:   ptr.To(true),
			RunAsNonRoot:             ptr.To(true),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{capabilityAll}},
		},
	}
	if spec.Resources != nil {
		container.Resources = *spec.Resources.DeepCopy()
	}

	podSpec := corev1.PodSpec{
		RestartPolicy:                 corev1.RestartPolicyNever,
		AutomountServiceAccountToken:  ptr.To(false),
		EnableServiceLinks:            ptr.To(false),
		TerminationGracePeriodSeconds: ptr.To(int64(60)),
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot:   ptr.To(true),
			RunAsUser:      ptr.To(replicationRunAsUser),
			RunAsGroup:     ptr.To(replicationRunAsUser),
			FSGroup:        ptr.To(replicationRunAsUser),
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Containers: []corev1.Container{container},
		Volumes:    volumes,
	}
	if pt := spec.PodTemplate; pt != nil {
		podSpec.NodeSelector = pt.NodeSelector
		podSpec.Tolerations = pt.Tolerations
		podSpec.Affinity = pt.Affinity
		podSpec.PriorityClassName = pt.PriorityClassName
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      replicationJobName(repl.Name, in.RunID, in.Bucket),
			Namespace: repl.Namespace,
			Labels:    labels,
			Annotations: map[string]string{
				annotationReplicationSource:      in.Bucket.Source,
				annotationReplicationDestination: in.Bucket.Destination,
				annotationReplicationRunID:       in.RunID,
				annotationReplicationSpecHash:    in.SpecHash,
				annotationReplicationMode:        string(mode),
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          ptr.To(backoffLimit),
			ActiveDeadlineSeconds: ptr.To(deadline),
			PodFailurePolicy: &batchv1.PodFailurePolicy{
				Rules: []batchv1.PodFailurePolicyRule{
					{
						// A safety guard tripped: retrying would either repeat
						// the refusal or delete another maxDeletes objects.
						Action: batchv1.PodFailurePolicyActionFailJob,
						OnExitCodes: &batchv1.PodFailurePolicyOnExitCodesRequirement{
							ContainerName: ptr.To(replicationContainerName),
							Operator:      batchv1.PodFailurePolicyOnExitCodesOpIn,
							Values:        []int32{replicationExitSourceEmpty, replicationExitMaxDeletes},
						},
					},
					{
						// Node drains and preemption are not the copy's fault.
						Action: batchv1.PodFailurePolicyActionIgnore,
						OnPodConditions: []batchv1.PodFailurePolicyOnPodConditionsPattern{{
							Type:   corev1.DisruptionTarget,
							Status: corev1.ConditionTrue,
						}},
					},
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels, Annotations: podAnnotations},
				Spec:       podSpec,
			},
		},
	}
}

// rcloneRemoteEnv configures an rclone S3 remote through environment
// variables. Credentials come from secretKeyRef so they never appear in the
// Job spec, the command line, or the operator's memory beyond an existence
// check.
func rcloneRemoteEnv(remote string, ep resolvedReplicationEndpoint) []corev1.EnvVar {
	prefix := "RCLONE_CONFIG_" + remote + "_"
	idKey, secretKey := garagev1beta1.ReplicationCredentialKeys(ep.Credentials)
	secretRef := func(key string) *corev1.EnvVarSource {
		return &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: ep.Credentials.Name},
			Key:                  key,
		}}
	}
	return []corev1.EnvVar{
		{Name: prefix + "TYPE", Value: "s3"},
		{Name: prefix + "PROVIDER", Value: "Other"},
		{Name: prefix + "ENDPOINT", Value: ep.URL},
		{Name: prefix + "REGION", Value: ep.Region},
		{Name: prefix + "FORCE_PATH_STYLE", Value: rcloneTrue},
		// Replication never creates buckets; a missing bucket is an error.
		{Name: prefix + "NO_CHECK_BUCKET", Value: rcloneTrue},
		{Name: prefix + "ACCESS_KEY_ID", ValueFrom: secretRef(idKey)},
		{Name: prefix + "SECRET_ACCESS_KEY", ValueFrom: secretRef(secretKey)},
	}
}

// RenderReplicationJob renders the Job replicating one bucket of repl for a
// run started at runStart, with already-resolved endpoints. The Garage
// contract tests use it to run the Job's script against real Garage
// processes; the controller itself goes through buildReplicationJob.
func RenderReplicationJob(repl *garagev1beta1.GarageReplication, bucket garagev1beta1.ReplicationBucket, runStart time.Time, image, srcURL, srcRegion, dstURL, dstRegion string) *batchv1.Job {
	return buildReplicationJob(replicationJobInput{
		Replication: repl,
		Bucket:      bucket,
		RunID:       replicationRunID(runStart),
		Image:       image,
		Source:      resolvedReplicationEndpoint{URL: srcURL, Region: srcRegion, Credentials: repl.Spec.Source.CredentialsSecretRef},
		Destination: resolvedReplicationEndpoint{URL: dstURL, Region: dstRegion, Credentials: repl.Spec.Destination.CredentialsSecretRef},
	})
}
