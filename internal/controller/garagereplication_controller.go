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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

const (
	// AnnotationTriggerSync starts a run of every bucket (including held
	// ones) as soon as no run is in progress. It is the only way to release a
	// hold. It is removed once the run starts. Use a unique value (e.g. a
	// timestamp) for each trigger.
	AnnotationTriggerSync = "garage.rajsingh.info/trigger-sync"

	kindGarageReplication = "GarageReplication"

	// Replication conditions.
	ConditionReplicationSynced    = "Synced"
	ConditionReplicationSuspended = "Suspended"

	// Ready=False reasons for an unusable configuration.
	ReplicationReasonCredentialsNotAllowed = "CredentialsNotAllowed"
	ReplicationReasonDestinationConflict   = "DestinationConflict"

	replicationActiveRequeue   = 30 * time.Second
	replicationNotReadyRequeue = 30 * time.Second
	replicationIdleRequeue     = time.Hour

	labelJobName = "batch.kubernetes.io/job-name"
)

// GarageReplicationReconciler reconciles a GarageReplication object. It only
// reads GarageClusters (to resolve S3 endpoints) and owns the per-bucket
// Jobs it creates; it never talks to Garage itself.
type GarageReplicationReconciler struct {
	client.Client
	// APIReader reads uncached: GarageReferenceGrants (like the bucket and
	// key controllers), and Jobs the cache does not show yet.
	APIReader     client.Reader
	Scheme        *runtime.Scheme
	EventRecorder record.EventRecorder
	ClusterDomain string
	// Image is the rclone image of the replication Jobs.
	Image string
	// Now is overridable in tests.
	Now func() time.Time
}

// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagereplications,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=garage.rajsingh.info,resources=garagereplications/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

func (r *GarageReplicationReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *GarageReplicationReconciler) image() string {
	if r.Image != "" {
		return r.Image
	}
	return DefaultReplicationImage
}

func (r *GarageReplicationReconciler) apiReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// Reconcile drives the replication runs of one GarageReplication.
func (r *GarageReplicationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	repl := &garagev1beta1.GarageReplication{}
	if err := r.Get(ctx, req.NamespacedName, repl); err != nil {
		if apierrors.IsNotFound(err) {
			deleteReplicationMetrics(req.Namespace, req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !repl.DeletionTimestamp.IsZero() {
		// Jobs are garbage-collected through their owner reference; object
		// data is never touched.
		deleteReplicationMetrics(repl.Namespace, repl.Name)
		return ctrl.Result{}, nil
	}

	now := r.now()
	status := &repl.Status
	original := status.DeepCopy()
	// A spec edit never releases a hold: only trigger-sync does.
	status.ObservedGeneration = repl.Generation

	jobs, err := r.listJobs(ctx, repl)
	if err != nil {
		return ctrl.Result{}, err
	}
	r.syncBucketStatuses(repl)
	if err := r.recordFinishedJobs(ctx, repl, jobs, now); err != nil {
		return ctrl.Result{}, err
	}

	src, dst, specHash, resolveErr := r.resolve(ctx, repl)
	if err := r.cancelObsoleteJobs(ctx, repl, jobs, now); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.pruneJobHistory(ctx, repl, jobs); err != nil {
		return ctrl.Result{}, err
	}
	r.completeRunIfDone(repl, jobs, now)

	result := ctrl.Result{}
	if resolveErr != nil {
		var cfgErr *replicationConfigError
		reason, message := "ResolveFailed", "the replication configuration could not be resolved"
		if errors.As(resolveErr, &cfgErr) {
			reason, message = cfgErr.reason, cfgErr.message
		} else {
			log.Error(resolveErr, "resolving GarageReplication")
		}
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type: garagev1beta1.ConditionReady, Status: metav1.ConditionFalse,
			Reason: reason, Message: message, ObservedGeneration: repl.Generation,
		})
		result.RequeueAfter = replicationNotReadyRequeue
	} else {
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{
			Type: garagev1beta1.ConditionReady, Status: metav1.ConditionTrue,
			Reason: "Resolved", Message: "source, destination and credentials are resolved", ObservedGeneration: repl.Generation,
		})
		trigger := repl.Annotations[AnnotationTriggerSync]
		consumeTrigger := false
		if status.CurrentRun == nil {
			r.holdUntriggeredMirrorBuckets(repl)
			r.startRunIfDue(repl, trigger, specHash, now)
		}
		if trigger != "" && status.CurrentRun != nil && status.CurrentRun.Reason == garagev1beta1.ReplicationRunTriggered && status.CurrentRun.Trigger == trigger {
			consumeTrigger = true
		}
		if status.CurrentRun != nil {
			// Persist the run before creating its Jobs so a crash never
			// starts the same run twice with different IDs.
			if err := r.writeStatus(ctx, repl, original, specHash, now); err != nil {
				return ctrl.Result{}, err
			}
			original = repl.Status.DeepCopy()
			if consumeTrigger {
				if err := r.removeTriggerAnnotation(ctx, repl, trigger); err != nil {
					return ctrl.Result{}, err
				}
			}
			if err := r.createRunJobs(ctx, repl, jobs, src, dst, specHash); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	if err := r.writeStatus(ctx, repl, original, specHash, now); err != nil {
		return ctrl.Result{}, err
	}
	updateReplicationMetrics(repl)

	switch {
	case result.RequeueAfter > 0:
	case status.CurrentRun != nil:
		result.RequeueAfter = replicationActiveRequeue
	case status.NextSyncTime != nil:
		wait := status.NextSyncTime.Sub(now)
		result.RequeueAfter = min(max(wait, time.Second), replicationIdleRequeue)
	default:
		result.RequeueAfter = replicationIdleRequeue
	}
	return result, nil
}

// replicationConfigError is a resolution failure caused by the user's
// configuration, reported on the Ready condition with a fixed reason.
type replicationConfigError struct {
	reason  string
	message string
}

func (e *replicationConfigError) Error() string { return e.reason + ": " + e.message }

func configErrorf(reason, format string, args ...any) error {
	return &replicationConfigError{reason: reason, message: fmt.Sprintf(format, args...)}
}

// resolve validates the spec, resolves both endpoints, checks that every
// referenced Secret/ConfigMap key exists and that the credentials Secrets
// opted in, and that no older GarageReplication writes the same destination
// buckets. Secret values are never read beyond checking that the keys are
// present and non-empty.
func (r *GarageReplicationReconciler) resolve(ctx context.Context, repl *garagev1beta1.GarageReplication) (resolvedReplicationEndpoint, resolvedReplicationEndpoint, string, error) {
	var src, dst resolvedReplicationEndpoint
	if _, err := garagev1beta1.ValidateGarageReplicationSpec(repl); err != nil {
		return src, dst, "", configErrorf("InvalidSpec", "%s", err.Error())
	}
	var err error
	if src, err = r.resolveEndpoint(ctx, repl, repl.Spec.Source, "source"); err != nil {
		return src, dst, "", err
	}
	if dst, err = r.resolveEndpoint(ctx, repl, repl.Spec.Destination, "destination"); err != nil {
		return src, dst, "", err
	}
	if garagev1beta1.NormalizeReplicationURL(src.URL) == garagev1beta1.NormalizeReplicationURL(dst.URL) {
		for _, b := range repl.Spec.Buckets {
			if b.Source == b.Destination {
				return src, dst, "", configErrorf("InvalidSpec", "spec.buckets: bucket %q would be replicated onto itself: source and destination resolve to the same endpoint", b.Source)
			}
		}
	}
	if err := r.checkDestinationConflict(ctx, repl, dst); err != nil {
		return src, dst, "", err
	}
	return src, dst, replicationSpecHash(repl, src, dst, r.image()), nil
}

func (r *GarageReplicationReconciler) resolveEndpoint(ctx context.Context, repl *garagev1beta1.GarageReplication, ep garagev1beta1.ReplicationEndpoint, side string) (resolvedReplicationEndpoint, error) {
	out := resolvedReplicationEndpoint{Credentials: ep.CredentialsSecretRef}
	switch {
	case ep.ClusterRef != nil:
		name, namespace := ep.ClusterRef.Name, ep.ClusterRef.Namespace
		if namespace == "" {
			namespace = repl.Namespace
		}
		if err := garagev1beta1.CheckReferenceGrant(ctx, r.apiReader(), kindGarageReplication, repl.Namespace, kindGarageCluster, namespace, name); err != nil {
			if garagev1beta1.IsReferenceGrantDenied(err) {
				return out, configErrorf("ReferenceNotGranted", "spec.%s.clusterRef %s/%s needs a GarageReferenceGrant in namespace %s allowing kind GarageReplication from namespace %s", side, namespace, name, namespace, repl.Namespace)
			}
			return out, err
		}
		url, region, err := r.clusterS3Endpoint(ctx, name, namespace)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return out, configErrorf("ClusterNotFound", "spec.%s.clusterRef: GarageCluster %s/%s not found", side, namespace, name)
			}
			if errors.Is(err, errReplicationEndpointUnresolved) {
				return out, configErrorf("EndpointUnresolved", "spec.%s.clusterRef: the S3 endpoint of GarageCluster %s/%s is not known yet", side, namespace, name)
			}
			return out, err
		}
		out.URL, out.Region = url, region
	case ep.Endpoint != nil:
		out.URL = ep.Endpoint.URL
		out.Region = ep.Endpoint.Region
		if out.Region == "" {
			out.Region = garagev1beta1.ReplicationDefaultRegion
		}
		if ca := ep.Endpoint.CABundleRef; ca != nil {
			out.CABundle = ca
			if err := r.checkCABundle(ctx, repl.Namespace, ca, side); err != nil {
				return out, err
			}
		}
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: ep.CredentialsSecretRef.Name, Namespace: repl.Namespace}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return out, configErrorf("SecretNotFound", "spec.%s.credentialsSecretRef: Secret %s not found in namespace %s", side, ep.CredentialsSecretRef.Name, repl.Namespace)
		}
		return out, err
	}
	// The Job sends the access key ID to an endpoint the creator of the
	// GarageReplication chooses: without this opt-in, the right to create one
	// would amount to reading any Secret of the namespace.
	if secret.Labels[garagev1beta1.LabelReplicationCredentials] != garagev1beta1.LabelReplicationCredentialsValue {
		return out, configErrorf(ReplicationReasonCredentialsNotAllowed, "spec.%s.credentialsSecretRef: Secret %s is not labelled %s=%s", side, secret.Name, garagev1beta1.LabelReplicationCredentials, garagev1beta1.LabelReplicationCredentialsValue)
	}
	idKey, secretKey := garagev1beta1.ReplicationCredentialKeys(ep.CredentialsSecretRef)
	for _, key := range []string{idKey, secretKey} {
		if len(secret.Data[key]) == 0 {
			return out, configErrorf("SecretKeyMissing", "spec.%s.credentialsSecretRef: Secret %s has no non-empty key %q", side, secret.Name, key)
		}
	}
	return out, nil
}

var errReplicationEndpointUnresolved = errors.New("S3 endpoint not known yet")

// clusterS3Endpoint returns the S3 URL (no path) and region of a GarageCluster.
func (r *GarageReplicationReconciler) clusterS3Endpoint(ctx context.Context, name, namespace string) (string, string, error) {
	cluster := &garagev1beta2.GarageCluster{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, cluster); err != nil {
		return "", "", err
	}
	u, err := ResolveS3Endpoint(cluster, r.ClusterDomain)
	if err != nil {
		return "", "", errReplicationEndpointUnresolved
	}
	u.Path = ""
	region := defaultS3Region
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.Region != "" {
		region = cluster.Spec.S3API.Region
	}
	return u.String(), region, nil
}

func (r *GarageReplicationReconciler) checkCABundle(ctx context.Context, namespace string, ca *garagev1beta1.ReplicationCABundleRef, side string) error {
	key := ca.Key
	if key == "" {
		key = garagev1beta1.ReplicationDefaultCABundleKey
	}
	cm := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Name: ca.Name, Namespace: namespace}, cm); err != nil {
		if apierrors.IsNotFound(err) {
			return configErrorf("CABundleNotFound", "spec.%s.endpoint.caBundleRef: ConfigMap %s not found", side, ca.Name)
		}
		return err
	}
	if cm.Data[key] == "" {
		return configErrorf("CABundleNotFound", "spec.%s.endpoint.caBundleRef: ConfigMap %s has no key %q", side, cm.Name, key)
	}
	return nil
}

// checkDestinationConflict applies destination exclusivity again after
// admission (two objects admitted concurrently, or created while the webhook
// was unavailable), and also compares resolved URLs, so a clusterRef and an
// endpoint that reach the same cluster are detected. The older object keeps
// the bucket; the other one runs nothing.
func (r *GarageReplicationReconciler) checkDestinationConflict(ctx context.Context, repl *garagev1beta1.GarageReplication, dst resolvedReplicationEndpoint) error {
	list := &garagev1beta1.GarageReplicationList{}
	if err := r.List(ctx, list); err != nil {
		return err
	}
	selfKey := garagev1beta1.ReplicationEndpointKey(repl.Spec.Destination, repl.Namespace)
	selfURL := garagev1beta1.NormalizeReplicationURL(dst.URL)
	for i := range list.Items {
		other := &list.Items[i]
		if other.UID == repl.UID || !other.DeletionTimestamp.IsZero() || !garagev1beta1.ReplicationPrecedes(other, repl) {
			continue
		}
		if garagev1beta1.ReplicationEndpointKey(other.Spec.Destination, other.Namespace) != selfKey && r.destinationURL(ctx, other) != selfURL {
			continue
		}
		for _, b := range repl.Spec.Buckets {
			if !slices.ContainsFunc(other.Spec.Buckets, func(ob garagev1beta1.ReplicationBucket) bool { return ob.Destination == b.Destination }) {
				continue
			}
			owner := "a GarageReplication in another namespace"
			if other.Namespace == repl.Namespace {
				owner = fmt.Sprintf("GarageReplication %q", other.Name)
			}
			return configErrorf(ReplicationReasonDestinationConflict, "destination bucket %q is already written by %s; a destination bucket can be written by only one GarageReplication", b.Destination, owner)
		}
	}
	return nil
}

// destinationURL returns the normalized destination URL of another
// GarageReplication, or "" when it cannot be resolved (then only its spec
// key is compared).
func (r *GarageReplicationReconciler) destinationURL(ctx context.Context, repl *garagev1beta1.GarageReplication) string {
	ep := repl.Spec.Destination
	switch {
	case ep.Endpoint != nil:
		return garagev1beta1.NormalizeReplicationURL(ep.Endpoint.URL)
	case ep.ClusterRef != nil:
		namespace := ep.ClusterRef.Namespace
		if namespace == "" {
			namespace = repl.Namespace
		}
		url, _, err := r.clusterS3Endpoint(ctx, ep.ClusterRef.Name, namespace)
		if err != nil {
			return ""
		}
		return garagev1beta1.NormalizeReplicationURL(url)
	}
	return ""
}

// replicationSpecHash covers everything that changes what a Job does.
// Schedule and suspend only change when runs happen and are excluded.
func replicationSpecHash(repl *garagev1beta1.GarageReplication, src, dst resolvedReplicationEndpoint, image string) string {
	spec := repl.Spec.DeepCopy()
	spec.Schedule = ""
	spec.Suspend = false
	spec.SuccessfulJobsHistoryLimit = nil
	spec.FailedJobsHistoryLimit = nil
	raw, _ := json.Marshal(struct {
		Spec  *garagev1beta1.GarageReplicationSpec
		Src   resolvedReplicationEndpoint
		Dst   resolvedReplicationEndpoint
		Image string
	}{spec, src, dst, image})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

func (r *GarageReplicationReconciler) listJobs(ctx context.Context, repl *garagev1beta1.GarageReplication) ([]batchv1.Job, error) {
	list := &batchv1.JobList{}
	if err := r.List(ctx, list, client.InNamespace(repl.Namespace), client.MatchingLabels{labelReplicationUID: string(repl.UID)}); err != nil {
		return nil, err
	}
	jobs := make([]batchv1.Job, 0, len(list.Items))
	for _, job := range list.Items {
		if metav1.IsControlledBy(&job, repl) {
			jobs = append(jobs, job)
		}
	}
	sort.Slice(jobs, func(i, j int) bool {
		if !jobs[i].CreationTimestamp.Equal(&jobs[j].CreationTimestamp) {
			return jobs[i].CreationTimestamp.Before(&jobs[j].CreationTimestamp)
		}
		return jobs[i].Name < jobs[j].Name
	})
	return jobs, nil
}

// jobDestination is the destination bucket a Job writes, the key of its
// bucket status.
func jobDestination(job *batchv1.Job) string {
	return job.Annotations[annotationReplicationDestination]
}

// syncBucketStatuses keeps one status entry per spec bucket, in spec order,
// keyed by destination. The source follows the spec.
func (r *GarageReplicationReconciler) syncBucketStatuses(repl *garagev1beta1.GarageReplication) {
	existing := map[string]garagev1beta1.ReplicationBucketStatus{}
	for _, b := range repl.Status.Buckets {
		existing[b.Destination] = b
	}
	out := make([]garagev1beta1.ReplicationBucketStatus, 0, len(repl.Spec.Buckets))
	for _, b := range repl.Spec.Buckets {
		entry, ok := existing[b.Destination]
		if !ok {
			entry = garagev1beta1.ReplicationBucketStatus{Destination: b.Destination}
		}
		entry.Source = b.Source
		out = append(out, entry)
	}
	repl.Status.Buckets = out
}

func bucketStatusFor(repl *garagev1beta1.GarageReplication, destination string) *garagev1beta1.ReplicationBucketStatus {
	for i := range repl.Status.Buckets {
		if repl.Status.Buckets[i].Destination == destination {
			return &repl.Status.Buckets[i]
		}
	}
	return nil
}

// recordCancelled records a Job that stopped before it finished.
func recordCancelled(bucket *garagev1beta1.ReplicationBucketStatus, job, runID string, mode garagev1beta1.ReplicationMode, now time.Time) {
	t := metav1.NewTime(now)
	bucket.ActiveJob = ""
	bucket.LastJob = job
	bucket.LastRunID = runID
	bucket.LastResult = garagev1beta1.ReplicationResultCancelled
	bucket.LastMode = mode
	bucket.LastCompletionTime = &t
	bucket.LastStatistics = nil
	bucket.LastVerification = ""
	bucket.LastError = ""
}

// recordFinishedJobs copies the outcome of every finished Job not recorded
// yet into the bucket status, oldest first, and notes active Jobs.
func (r *GarageReplicationReconciler) recordFinishedJobs(ctx context.Context, repl *garagev1beta1.GarageReplication, jobs []batchv1.Job, now time.Time) error {
	listed := map[string]bool{}
	for i := range jobs {
		listed[jobs[i].Name] = true
	}
	for i := range repl.Status.Buckets {
		bucket := &repl.Status.Buckets[i]
		previous := bucket.ActiveJob
		bucket.ActiveJob = ""
		if previous == "" || listed[previous] {
			continue
		}
		// The Job recorded as active is gone from the cache. Confirm with an
		// uncached read so a Job created a moment ago is not mistaken for a
		// deleted one; then the deletion was someone stopping the run.
		job := &batchv1.Job{}
		err := r.apiReader().Get(ctx, types.NamespacedName{Name: previous, Namespace: repl.Namespace}, job)
		if err == nil {
			bucket.ActiveJob = previous
			continue
		}
		if !apierrors.IsNotFound(err) {
			return err
		}
		runID := ""
		if run := repl.Status.CurrentRun; run != nil {
			runID = run.ID
		}
		recordCancelled(bucket, previous, runID, garagev1beta1.EffectiveReplicationMode(&repl.Spec), now)
		r.event(repl, corev1.EventTypeNormal, "SyncCancelled", "Job %s was deleted before it finished", previous)
	}
	for i := range jobs {
		job := &jobs[i]
		bucket := bucketStatusFor(repl, jobDestination(job))
		if bucket == nil {
			continue
		}
		finished, _, _ := replicationJobFinished(job)
		if !finished {
			if job.DeletionTimestamp.IsZero() {
				bucket.ActiveJob = job.Name
			}
			continue
		}
		runID := job.Annotations[annotationReplicationRunID]
		if bucket.LastJob == job.Name || replicationRunIDLess(runID, bucket.LastRunID) {
			continue
		}
		pods := &corev1.PodList{}
		if err := r.List(ctx, pods, client.InNamespace(job.Namespace), client.MatchingLabels{labelJobName: job.Name}); err != nil {
			return err
		}
		outcome := summarizeReplicationJob(job, pods.Items)
		completed := metav1.NewTime(now)
		if job.Status.CompletionTime != nil {
			completed = *job.Status.CompletionTime
		} else {
			for _, c := range job.Status.Conditions {
				if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
					completed = c.LastTransitionTime
				}
			}
		}
		bucket.LastJob = job.Name
		bucket.LastRunID = runID
		bucket.LastResult = outcome.Result
		bucket.LastMode = garagev1beta1.ReplicationMode(job.Annotations[annotationReplicationMode])
		bucket.LastCompletionTime = &completed
		bucket.LastStatistics = outcome.Stats
		bucket.LastVerification = outcome.Verification
		bucket.LastError = outcome.Reason
		if outcome.Result == garagev1beta1.ReplicationResultSucceeded {
			bucket.LastSuccessfulTime = &completed
			continue
		}
		if hold := replicationSafetyHold(outcome.Reason); hold != "" {
			bucket.Hold = hold
		}
		r.event(repl, corev1.EventTypeWarning, "SyncFailed", "bucket %s -> %s failed: %s", bucket.Source, bucket.Destination, outcome.Reason)
	}
	return nil
}

// cancelObsoleteJobs deletes active Jobs whose destination left the spec or
// now has another source, or whose mode deletes more than the current spec
// allows.
func (r *GarageReplicationReconciler) cancelObsoleteJobs(ctx context.Context, repl *garagev1beta1.GarageReplication, jobs []batchv1.Job, now time.Time) error {
	wanted := map[string]string{}
	for _, b := range repl.Spec.Buckets {
		wanted[b.Destination] = b.Source
	}
	mode := garagev1beta1.EffectiveReplicationMode(&repl.Spec)
	for i := range jobs {
		job := &jobs[i]
		if finished, _, _ := replicationJobFinished(job); finished || !job.DeletionTimestamp.IsZero() {
			continue
		}
		destination := jobDestination(job)
		jobMode := garagev1beta1.ReplicationMode(job.Annotations[annotationReplicationMode])
		why := ""
		switch source, ok := wanted[destination]; {
		case !ok:
			why = "its destination bucket was removed from spec.buckets"
		case source != job.Annotations[annotationReplicationSource]:
			why = "its destination bucket now has another source"
		case jobMode == garagev1beta1.ReplicationModeMirror && mode != garagev1beta1.ReplicationModeMirror:
			why = fmt.Sprintf("it runs in mode %s and spec.mode is now %s", jobMode, mode)
		default:
			continue
		}
		if err := r.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationForeground)); client.IgnoreNotFound(err) != nil {
			return err
		}
		r.event(repl, corev1.EventTypeNormal, "SyncCancelled", "cancelled Job %s because %s", job.Name, why)
		if bucket := bucketStatusFor(repl, destination); bucket != nil {
			recordCancelled(bucket, job.Name, job.Annotations[annotationReplicationRunID], jobMode, now)
		}
	}
	return nil
}

// pruneJobHistory keeps the configured number of finished Jobs. Only Jobs
// already recorded in status are deleted.
func (r *GarageReplicationReconciler) pruneJobHistory(ctx context.Context, repl *garagev1beta1.GarageReplication, jobs []batchv1.Job) error {
	keepSucceeded, keepFailed := int32(1), int32(3)
	if repl.Spec.SuccessfulJobsHistoryLimit != nil {
		keepSucceeded = *repl.Spec.SuccessfulJobsHistoryLimit
	}
	if repl.Spec.FailedJobsHistoryLimit != nil {
		keepFailed = *repl.Spec.FailedJobsHistoryLimit
	}
	var succeeded, failed []*batchv1.Job
	for i := len(jobs) - 1; i >= 0; i-- { // newest first
		job := &jobs[i]
		finished, ok, _ := replicationJobFinished(job)
		if !finished || !job.DeletionTimestamp.IsZero() {
			continue
		}
		if ok {
			succeeded = append(succeeded, job)
		} else {
			failed = append(failed, job)
		}
	}
	prune := func(list []*batchv1.Job, keep int32) error {
		for idx, job := range list {
			if int32(idx) < keep {
				continue
			}
			bucket := bucketStatusFor(repl, jobDestination(job))
			if bucket != nil && bucket.LastJob != job.Name && !replicationRunIDLess(job.Annotations[annotationReplicationRunID], bucket.LastRunID) {
				continue // not recorded yet
			}
			if err := r.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground)); client.IgnoreNotFound(err) != nil {
				return err
			}
		}
		return nil
	}
	if err := prune(succeeded, keepSucceeded); err != nil {
		return err
	}
	return prune(failed, keepFailed)
}

// completeRunIfDone closes the current run once every participating bucket
// still in the spec has a recorded result for it and no Job of the run is
// active.
func (r *GarageReplicationReconciler) completeRunIfDone(repl *garagev1beta1.GarageReplication, jobs []batchv1.Job, now time.Time) {
	run := repl.Status.CurrentRun
	if run == nil {
		return
	}
	for i := range jobs {
		if finished, _, _ := replicationJobFinished(&jobs[i]); !finished && jobs[i].Annotations[annotationReplicationRunID] == run.ID {
			return
		}
	}
	allSucceeded := true
	for _, destination := range run.Buckets {
		bucket := bucketStatusFor(repl, destination)
		if bucket == nil {
			continue // removed from spec during the run
		}
		if bucket.LastRunID != run.ID {
			return // not run yet
		}
		if bucket.LastResult != garagev1beta1.ReplicationResultSucceeded {
			allSucceeded = false
		}
	}
	t := metav1.NewTime(now)
	done := run.DeepCopy()
	done.CompletionTime = &t
	done.Result = garagev1beta1.ReplicationResultSucceeded
	repl.Status.LastSyncTime = &t
	if allSucceeded {
		repl.Status.LastSuccessfulSyncTime = &t
		r.event(repl, corev1.EventTypeNormal, "SyncSucceeded", "%s run %s replicated %d bucket(s)", run.Reason, run.ID, len(run.Buckets))
	} else {
		done.Result = garagev1beta1.ReplicationResultFailed
		r.event(repl, corev1.EventTypeWarning, "SyncFailed", "%s run %s finished with failed buckets", run.Reason, run.ID)
	}
	repl.Status.LastRun = done
	repl.Status.CurrentRun = nil
}

// holdUntriggeredMirrorBuckets puts the AwaitingTrigger hold on every bucket
// that has not run in Mirror mode yet while spec.mode is Mirror, so the first
// deletions only happen after a person triggers them. The hold is dropped
// again when the mode goes back to Copy, which never deletes. Other holds are
// left alone.
func (r *GarageReplicationReconciler) holdUntriggeredMirrorBuckets(repl *garagev1beta1.GarageReplication) {
	mirror := garagev1beta1.EffectiveReplicationMode(&repl.Spec) == garagev1beta1.ReplicationModeMirror
	for i := range repl.Status.Buckets {
		bucket := &repl.Status.Buckets[i]
		switch {
		case !mirror && bucket.Hold == garagev1beta1.ReplicationHoldAwaitingTrigger:
			bucket.Hold = ""
		case mirror && bucket.Hold == "" && bucket.LastMode != garagev1beta1.ReplicationModeMirror:
			bucket.Hold = garagev1beta1.ReplicationHoldAwaitingTrigger
		}
	}
}

// startRunIfDue starts a run when one is triggered, when the object was
// just created, or when the schedule says so. Runs never overlap: missed
// schedule times while a run is active collapse into one. A trigger releases
// every hold; other runs skip held buckets.
func (r *GarageReplicationReconciler) startRunIfDue(repl *garagev1beta1.GarageReplication, trigger, specHash string, now time.Time) {
	status := &repl.Status
	var reason garagev1beta1.ReplicationRunReason
	switch {
	case trigger != "":
		reason = garagev1beta1.ReplicationRunTriggered
	case repl.Spec.Suspend:
		return
	case status.LastScheduleTime == nil:
		reason = garagev1beta1.ReplicationRunInitial
	default:
		sched, err := garagev1beta1.ParseReplicationSchedule(repl.Spec.Schedule)
		if err != nil || sched == nil {
			return
		}
		if now.Before(sched.Next(status.LastScheduleTime.Time)) {
			return
		}
		reason = garagev1beta1.ReplicationRunScheduled
	}

	var buckets []string
	for _, b := range repl.Spec.Buckets {
		bucket := bucketStatusFor(repl, b.Destination)
		if reason == garagev1beta1.ReplicationRunTriggered {
			if bucket != nil {
				bucket.Hold = ""
			}
		} else if bucket != nil && bucket.Hold != "" {
			continue
		}
		buckets = append(buckets, b.Destination)
	}
	start := metav1.NewTime(now)
	status.LastScheduleTime = &start
	if reason == garagev1beta1.ReplicationRunTriggered {
		status.LastOperation = &garagev1beta1.LastOperationStatus{Type: "TriggerSync", TriggeredAt: &start, Succeeded: true}
	}
	if len(buckets) == 0 {
		r.event(repl, corev1.EventTypeWarning, "SyncSkipped", "every bucket is held (see status.buckets[].hold); set the %s annotation to run them", AnnotationTriggerSync)
		return
	}
	runID := replicationRunID(now)
	if status.LastRun != nil && !replicationRunIDLess(status.LastRun.ID, runID) {
		// Two runs in the same second (a trigger right after a run):
		// keep run IDs, and therefore Job names, strictly increasing.
		runID = replicationRunID(time.Unix(parseReplicationRunID(status.LastRun.ID)+1, 0))
	}
	status.CurrentRun = &garagev1beta1.ReplicationRun{
		ID: runID, Reason: reason, StartTime: start, SpecHash: specHash, Buckets: buckets,
	}
	if reason == garagev1beta1.ReplicationRunTriggered {
		status.CurrentRun.Trigger = trigger
	}
	r.event(repl, corev1.EventTypeNormal, "SyncStarted", "%s run %s started for %d bucket(s)", reason, runID, len(buckets))
}

// createRunJobs creates the current run's missing Jobs, at most
// maxConcurrentBuckets active at a time.
func (r *GarageReplicationReconciler) createRunJobs(ctx context.Context, repl *garagev1beta1.GarageReplication, jobs []batchv1.Job, src, dst resolvedReplicationEndpoint, specHash string) error {
	run := repl.Status.CurrentRun
	maxActive := int32(1)
	if t := repl.Spec.Transfer; t != nil && t.MaxConcurrentBuckets > 0 {
		maxActive = t.MaxConcurrentBuckets
	}
	existing := map[string]bool{}
	active := int32(0)
	for i := range jobs {
		existing[jobs[i].Name] = true
		if finished, _, _ := replicationJobFinished(&jobs[i]); !finished {
			active++
		}
	}
	for _, b := range repl.Spec.Buckets {
		if !slices.Contains(run.Buckets, b.Destination) {
			continue
		}
		bucket := bucketStatusFor(repl, b.Destination)
		name := replicationJobName(repl.Name, run.ID, b)
		if existing[name] || (bucket != nil && !replicationRunIDLess(bucket.LastRunID, run.ID)) {
			continue
		}
		if bucket != nil && bucket.ActiveJob != "" {
			continue // a Job of an earlier run still runs for this bucket
		}
		if active >= maxActive {
			return nil
		}
		job := buildReplicationJob(replicationJobInput{
			Replication: repl, Bucket: b, RunID: run.ID,
			SpecHash: specHash, Image: r.image(), Source: src, Destination: dst,
		})
		if err := controllerutil.SetControllerReference(repl, job, r.Scheme); err != nil {
			return err
		}
		if err := r.Create(ctx, job); err != nil {
			if apierrors.IsAlreadyExists(err) {
				continue
			}
			return err
		}
		active++
		if bucket != nil {
			bucket.ActiveJob = job.Name
		}
	}
	return nil
}

func (r *GarageReplicationReconciler) removeTriggerAnnotation(ctx context.Context, repl *garagev1beta1.GarageReplication, value string) error {
	latest := &garagev1beta1.GarageReplication{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(repl), latest); err != nil {
		return err
	}
	if latest.Annotations[AnnotationTriggerSync] != value {
		return nil
	}
	patch := client.MergeFrom(latest.DeepCopy())
	delete(latest.Annotations, AnnotationTriggerSync)
	if err := r.Patch(ctx, latest, patch); err != nil {
		return err
	}
	repl.Annotations = latest.Annotations
	repl.ResourceVersion = latest.ResourceVersion
	return nil
}

// writeStatus derives phase, conditions and the next sync time, then writes
// status when it changed.
func (r *GarageReplicationReconciler) writeStatus(ctx context.Context, repl *garagev1beta1.GarageReplication, original *garagev1beta1.GarageReplicationStatus, specHash string, now time.Time) error {
	status := &repl.Status
	ready := meta.IsStatusConditionTrue(status.Conditions, garagev1beta1.ConditionReady)

	status.NextSyncTime = nil
	if sched, err := garagev1beta1.ParseReplicationSchedule(repl.Spec.Schedule); err == nil && sched != nil && !repl.Spec.Suspend {
		base := now
		if status.LastScheduleTime != nil {
			base = status.LastScheduleTime.Time
		}
		next := metav1.NewTime(sched.Next(base))
		status.NextSyncTime = &next
	}

	safetyHold, awaitingTrigger := false, false
	for _, b := range status.Buckets {
		switch b.Hold {
		case "":
		case garagev1beta1.ReplicationHoldAwaitingTrigger:
			awaitingTrigger = true
		default:
			safetyHold = true
		}
	}
	switch {
	case status.CurrentRun != nil:
		status.Phase = garagev1beta1.ReplicationPhaseSyncing
	case !ready:
		status.Phase = garagev1beta1.ReplicationPhasePending
	case repl.Spec.Suspend:
		status.Phase = garagev1beta1.ReplicationPhaseSuspended
	case status.LastRun != nil && status.LastRun.Result == garagev1beta1.ReplicationResultFailed:
		status.Phase = garagev1beta1.ReplicationPhaseFailed
	default:
		status.Phase = garagev1beta1.ReplicationPhaseIdle
	}

	synced := metav1.Condition{Type: ConditionReplicationSynced, Status: metav1.ConditionFalse, ObservedGeneration: repl.Generation}
	switch {
	case safetyHold:
		synced.Reason, synced.Message = "SafetyHold", fmt.Sprintf("a safety guard stopped at least one bucket (see status.buckets[].hold); check both sides, then set the %s annotation to resume", AnnotationTriggerSync)
	case awaitingTrigger:
		synced.Reason, synced.Message = "AwaitingTrigger", fmt.Sprintf("mode Mirror deletes destination objects; its first run starts on the %s annotation", AnnotationTriggerSync)
	case status.LastRun == nil:
		synced.Reason, synced.Message = "NeverSynced", "no run has finished yet"
	case status.LastRun.Result != garagev1beta1.ReplicationResultSucceeded:
		synced.Reason, synced.Message = "SyncFailed", "the last run had failed buckets (see status.buckets[].lastError)"
	case specHash != "" && status.LastRun.SpecHash != specHash:
		synced.Reason, synced.Message = "ConfigChanged", "the configuration changed since the last successful run"
	default:
		synced.Status, synced.Reason, synced.Message = metav1.ConditionTrue, "Synced", "every bucket succeeded in the last run"
	}
	meta.SetStatusCondition(&status.Conditions, synced)

	suspended := metav1.Condition{Type: ConditionReplicationSuspended, Status: metav1.ConditionFalse, Reason: "Active", Message: "runs start on schedule", ObservedGeneration: repl.Generation}
	if repl.Spec.Suspend {
		suspended.Status, suspended.Reason, suspended.Message = metav1.ConditionTrue, "Suspended", "spec.suspend is true; no scheduled run starts"
	}
	meta.SetStatusCondition(&status.Conditions, suspended)

	if equality.Semantic.DeepEqual(original, status) {
		return nil
	}
	return r.Status().Update(ctx, repl)
}

func (r *GarageReplicationReconciler) event(repl *garagev1beta1.GarageReplication, eventType, reason, format string, args ...any) {
	if r.EventRecorder == nil {
		return
	}
	r.EventRecorder.Eventf(repl, eventType, reason, format, args...)
}

// parseReplicationRunID returns the Unix time of a run ID, or -1 for an
// empty or malformed ID.
func parseReplicationRunID(id string) int64 {
	n, err := strconv.ParseInt(id, 36, 64)
	if err != nil {
		return -1
	}
	return n
}

// replicationRunIDLess orders run IDs by time; an empty ID sorts first.
func replicationRunIDLess(a, b string) bool {
	return parseReplicationRunID(a) < parseReplicationRunID(b)
}

// SetupWithManager sets up the controller with the Manager. Status-only
// writes do not re-enter Reconcile; every path returns RequeueAfter.
func (r *GarageReplicationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&garagev1beta1.GarageReplication{}, builder.WithPredicates(predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.AnnotationChangedPredicate{},
		))).
		Owns(&batchv1.Job{}).
		Named("garagereplication").
		Complete(r)
}
