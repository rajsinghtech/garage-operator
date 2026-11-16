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
	"math"
	"strconv"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
)

const (
	replicationTerminationPrefix = "garage-replication/v1"
	// replicationExitTerminated is the script's exit code after SIGTERM.
	replicationExitTerminated = 143
)

// replicationTermination is the parsed termination message of the
// replication container.
type replicationTermination struct {
	ExitCode     int
	Reason       string
	Verification string
	Stats        *garagev1beta1.ReplicationStatistics
}

// parseReplicationTermination parses the single line written by
// replicationScript. It returns ok=false for anything else (a truncated
// message, a Pod killed before the script finished), in which case no
// statistics are reported rather than zeros.
func parseReplicationTermination(msg string) (replicationTermination, bool) {
	line := strings.TrimSpace(msg)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) == 0 || fields[0] != replicationTerminationPrefix {
		return replicationTermination{}, false
	}
	values := map[string]string{}
	for _, f := range fields[1:] {
		k, v, found := strings.Cut(f, "=")
		if !found {
			continue
		}
		values[k] = v
	}
	exit, err := strconv.Atoi(values["exit"])
	if err != nil {
		return replicationTermination{}, false
	}
	out := replicationTermination{
		ExitCode:     exit,
		Reason:       values["reason"],
		Verification: values["verify"],
	}
	if values["stats"] == "1" {
		num := func(k string) int64 {
			n, _ := strconv.ParseInt(values[k], 10, 64)
			return n
		}
		elapsed, _ := strconv.ParseFloat(values["elapsedTime"], 64)
		out.Stats = &garagev1beta1.ReplicationStatistics{
			Transfers:      num("transfers"),
			Bytes:          num("bytes"),
			Checks:         num("checks"),
			Deletes:        num("deletes"),
			Errors:         num("errors"),
			ElapsedSeconds: int64(math.Round(elapsed)),
		}
		if d, err := strconv.ParseInt(values["differences"], 10, 64); err == nil {
			out.Stats.Differences = &d
		}
	}
	return out, true
}

// replicationJobFinished reports whether a Job reached a terminal condition
// and whether it succeeded.
func replicationJobFinished(job *batchv1.Job) (finished, succeeded bool, failureReason string) {
	for _, c := range job.Status.Conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		switch c.Type {
		case batchv1.JobComplete:
			return true, true, ""
		case batchv1.JobFailed:
			return true, false, c.Reason
		}
	}
	return false, false, ""
}

// replicationJobOutcome combines the Job's terminal condition with the
// termination message of its last Pod.
type replicationJobOutcome struct {
	Result       garagev1beta1.ReplicationResult
	Reason       garagev1beta1.ReplicationFailureReason
	Verification garagev1beta1.ReplicationVerificationResult
	Stats        *garagev1beta1.ReplicationStatistics
}

func summarizeReplicationJob(job *batchv1.Job, pods []corev1.Pod) replicationJobOutcome {
	_, succeeded, jobFailureReason := replicationJobFinished(job)
	var term replicationTermination
	parsed := false
	if pod := latestReplicationPod(pods); pod != nil {
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.Name != replicationContainerName || cs.State.Terminated == nil {
				continue
			}
			term, parsed = parseReplicationTermination(cs.State.Terminated.Message)
		}
	}
	out := replicationJobOutcome{}
	if parsed {
		out.Stats = term.Stats
		switch v := garagev1beta1.ReplicationVerificationResult(term.Verification); v {
		case garagev1beta1.ReplicationVerificationPassed, garagev1beta1.ReplicationVerificationFailed:
			out.Verification = v
		}
	}
	if succeeded {
		out.Result = garagev1beta1.ReplicationResultSucceeded
		return out
	}
	out.Result = garagev1beta1.ReplicationResultFailed
	reason := garagev1beta1.ReplicationFailureReason(term.Reason)
	switch {
	case jobFailureReason == batchv1.JobReasonDeadlineExceeded:
		out.Reason = garagev1beta1.ReplicationFailureDeadlineExceeded
	case parsed && knownReplicationReason(reason):
		out.Reason = reason
	case parsed && term.ExitCode != 0 && term.ExitCode != replicationExitTerminated:
		out.Reason = garagev1beta1.ReplicationFailureTransferErrors
	default:
		out.Reason = garagev1beta1.ReplicationFailureUnknown
	}
	return out
}

// knownReplicationReason reports whether the script may report r. Anything
// else in a termination message is not trusted into status.
func knownReplicationReason(r garagev1beta1.ReplicationFailureReason) bool {
	switch r {
	case garagev1beta1.ReplicationFailureAuthFailed, garagev1beta1.ReplicationFailureBucketNotFound,
		garagev1beta1.ReplicationFailureEndpointUnreachable, garagev1beta1.ReplicationFailureSourceEmpty,
		garagev1beta1.ReplicationFailureMaxDeletesExceeded, garagev1beta1.ReplicationFailureVerificationFailed,
		garagev1beta1.ReplicationFailureTransferErrors:
		return true
	}
	return false
}

// replicationSafetyHold returns the hold a failure reason puts on its bucket,
// or "" when the next scheduled run may simply retry: re-running after these
// would repeat a refusal or delete another batch of objects.
func replicationSafetyHold(reason garagev1beta1.ReplicationFailureReason) garagev1beta1.ReplicationHold {
	switch reason {
	case garagev1beta1.ReplicationFailureSourceEmpty:
		return garagev1beta1.ReplicationHoldSourceEmpty
	case garagev1beta1.ReplicationFailureMaxDeletesExceeded:
		return garagev1beta1.ReplicationHoldMaxDeletesExceeded
	}
	return ""
}

func latestReplicationPod(pods []corev1.Pod) *corev1.Pod {
	var latest *corev1.Pod
	for i := range pods {
		p := &pods[i]
		if latest == nil || latest.CreationTimestamp.Before(&p.CreationTimestamp) ||
			(latest.CreationTimestamp.Equal(&p.CreationTimestamp) && latest.Name < p.Name) {
			latest = p
		}
	}
	return latest
}
