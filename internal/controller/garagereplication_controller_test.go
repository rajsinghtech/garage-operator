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
	"encoding/json"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

const (
	replTestNamespace = "dr"
	replTestName      = "prod-to-dr"
	replTestSrcSecret = "src-creds"
	replTestDstSecret = "dst-creds"
	replTestSecretID  = "GKsecretmaterialid0000000"
	replTestSecretKey = "super-secret-access-key-material-0123456789"
	replTestDstURL    = "https://s3.dr.example.com"
)

type replicationHarness struct {
	t      *testing.T
	r      *GarageReplicationReconciler
	c      client.Client
	now    time.Time
	scheme *runtime.Scheme
}

func newReplicationHarness(t *testing.T, repl *garagev1beta1.GarageReplication, extra ...client.Object) *replicationHarness {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, batchv1.AddToScheme, garagev1beta1.AddToScheme, garagev1beta2.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	objects := []client.Object{
		replicationTestSecret(replTestSrcSecret, true),
		replicationTestSecret(replTestDstSecret, true),
	}
	if repl != nil {
		objects = append(objects, repl)
	}
	objects = append(objects, extra...)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&garagev1beta1.GarageReplication{}, &batchv1.Job{}).
		WithObjects(objects...).Build()
	h := &replicationHarness{t: t, c: c, scheme: scheme, now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	h.r = &GarageReplicationReconciler{Client: c, APIReader: c, Scheme: scheme, ClusterDomain: "cluster.local", Now: func() time.Time { return h.now }}
	return h
}

func replicationTestSecret(name string, optedIn bool) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: replTestNamespace},
		Data: map[string][]byte{
			garagev1beta1.ReplicationDefaultAccessKeyIDKey:     []byte(replTestSecretID),
			garagev1beta1.ReplicationDefaultSecretAccessKeyKey: []byte(replTestSecretKey),
		},
	}
	if optedIn {
		s.Labels = map[string]string{garagev1beta1.LabelReplicationCredentials: "true"}
	}
	return s
}

func replicationFixture() *garagev1beta1.GarageReplication {
	return &garagev1beta1.GarageReplication{
		ObjectMeta: metav1.ObjectMeta{
			Name: replTestName, Namespace: replTestNamespace, UID: types.UID("repl-uid"), Generation: 1,
			CreationTimestamp: metav1.NewTime(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)),
		},
		Spec: garagev1beta1.GarageReplicationSpec{
			Source: garagev1beta1.ReplicationEndpoint{
				Endpoint:             &garagev1beta1.ReplicationS3Endpoint{URL: "https://s3.prod.example.com"},
				CredentialsSecretRef: garagev1beta1.ReplicationCredentialsRef{Name: replTestSrcSecret},
			},
			Destination: garagev1beta1.ReplicationEndpoint{
				Endpoint:             &garagev1beta1.ReplicationS3Endpoint{URL: replTestDstURL, Region: "dr"},
				CredentialsSecretRef: garagev1beta1.ReplicationCredentialsRef{Name: replTestDstSecret},
			},
			Buckets: []garagev1beta1.ReplicationBucket{
				{Source: "medias", Destination: "medias"},
				{Source: "pg-backups", Destination: "pg-backups-dr"},
			},
			Schedule: "*/15 * * * *",
		},
	}
}

// mirrorFixture is a one-bucket Mirror replication.
func mirrorFixture(maxDeletes int64) *garagev1beta1.GarageReplication {
	repl := replicationFixture()
	repl.Spec.Mode = garagev1beta1.ReplicationModeMirror
	repl.Spec.Mirror = &garagev1beta1.ReplicationMirrorConfig{MaxDeletes: maxDeletes}
	repl.Spec.Buckets = repl.Spec.Buckets[:1]
	return repl
}

func (h *replicationHarness) reconcile() ctrl.Result {
	h.t.Helper()
	res, err := h.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: replTestName, Namespace: replTestNamespace}})
	if err != nil {
		h.t.Fatalf("reconcile: %v", err)
	}
	return res
}

func (h *replicationHarness) get() *garagev1beta1.GarageReplication {
	h.t.Helper()
	repl := &garagev1beta1.GarageReplication{}
	if err := h.c.Get(context.Background(), types.NamespacedName{Name: replTestName, Namespace: replTestNamespace}, repl); err != nil {
		h.t.Fatal(err)
	}
	return repl
}

func (h *replicationHarness) update(mutate func(*garagev1beta1.GarageReplication)) {
	h.t.Helper()
	repl := h.get()
	mutate(repl)
	repl.Generation++
	if err := h.c.Update(context.Background(), repl); err != nil {
		h.t.Fatal(err)
	}
}

func (h *replicationHarness) trigger(value string) {
	h.t.Helper()
	h.update(func(r *garagev1beta1.GarageReplication) {
		if r.Annotations == nil {
			r.Annotations = map[string]string{}
		}
		r.Annotations[AnnotationTriggerSync] = value
	})
}

func (h *replicationHarness) jobs() []batchv1.Job {
	h.t.Helper()
	list := &batchv1.JobList{}
	if err := h.c.List(context.Background(), list, client.InNamespace(replTestNamespace)); err != nil {
		h.t.Fatal(err)
	}
	return list.Items
}

func (h *replicationHarness) activeJobs() []batchv1.Job {
	var out []batchv1.Job
	for _, j := range h.jobs() {
		if finished, _, _ := replicationJobFinished(&j); !finished {
			out = append(out, j)
		}
	}
	return out
}

// finishJob marks a Job finished the way the Job controller would and
// creates its Pod with the given termination message.
func (h *replicationHarness) finishJob(name string, succeeded bool, jobReason, message string) {
	h.t.Helper()
	job := &batchv1.Job{}
	if err := h.c.Get(context.Background(), types.NamespacedName{Name: name, Namespace: replTestNamespace}, job); err != nil {
		h.t.Fatal(err)
	}
	t := metav1.NewTime(h.now)
	cond := batchv1.JobCondition{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: jobReason, LastTransitionTime: t}
	if succeeded {
		cond.Type = batchv1.JobComplete
		job.Status.CompletionTime = &t
	}
	job.Status.Conditions = append(job.Status.Conditions, cond)
	if err := h.c.Status().Update(context.Background(), job); err != nil {
		h.t.Fatal(err)
	}
	exit := int32(0)
	if !succeeded {
		exit = 1
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-pod", Namespace: replTestNamespace, Labels: map[string]string{labelJobName: name}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name:  replicationContainerName,
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: exit, Message: message}},
		}}},
	}
	if err := h.c.Create(context.Background(), pod); err != nil {
		h.t.Fatal(err)
	}
}

const (
	replTestSuccessMessage    = "garage-replication/v1 exit=0 reason= verify= differences= stats=1 transfers=6 bytes=37 checks=2 deletes=0 errors=0 elapsedTime=1.6\n"
	replTestMaxDeletesMessage = "garage-replication/v1 exit=65 reason=MaxDeletesExceeded verify= differences= stats=1 transfers=0 bytes=0 checks=5 deletes=10 errors=0 elapsedTime=1"
)

func bucketStatus(t *testing.T, repl *garagev1beta1.GarageReplication, destination string) garagev1beta1.ReplicationBucketStatus {
	t.Helper()
	for _, b := range repl.Status.Buckets {
		if b.Destination == destination {
			return b
		}
	}
	t.Fatalf("no status for destination bucket %s", destination)
	return garagev1beta1.ReplicationBucketStatus{}
}

func readyCondition(t *testing.T, repl *garagev1beta1.GarageReplication) *metav1.Condition {
	t.Helper()
	c := meta.FindStatusCondition(repl.Status.Conditions, garagev1beta1.ConditionReady)
	if c == nil {
		t.Fatal("no Ready condition")
	}
	return c
}

func TestReplicationInitialRunRunsBucketsOneAtATimeAndRecordsResults(t *testing.T) {
	h := newReplicationHarness(t, replicationFixture())

	h.reconcile()
	h.reconcile() // idempotent: no second Job for the same work
	jobs := h.jobs()
	if len(jobs) != 1 {
		t.Fatalf("want 1 Job (maxConcurrentBuckets defaults to 1), got %d", len(jobs))
	}
	repl := h.get()
	if repl.Status.Phase != garagev1beta1.ReplicationPhaseSyncing || repl.Status.CurrentRun == nil || repl.Status.CurrentRun.Reason != garagev1beta1.ReplicationRunInitial {
		t.Fatalf("want an Initial run in progress, got phase=%s run=%+v", repl.Status.Phase, repl.Status.CurrentRun)
	}
	if !meta.IsStatusConditionTrue(repl.Status.Conditions, garagev1beta1.ConditionReady) {
		t.Fatalf("Ready should be True: %+v", repl.Status.Conditions)
	}

	h.now = h.now.Add(time.Minute)
	h.finishJob(jobs[0].Name, true, "", replTestSuccessMessage)
	h.reconcile()
	repl = h.get()
	medias := bucketStatus(t, repl, "medias")
	if medias.LastResult != garagev1beta1.ReplicationResultSucceeded || medias.LastMode != garagev1beta1.ReplicationModeCopy ||
		medias.LastStatistics == nil || medias.LastStatistics.Transfers != 6 || medias.LastStatistics.Bytes != 37 || medias.LastStatistics.ElapsedSeconds != 2 {
		t.Fatalf("medias not recorded: %+v stats=%+v", medias, medias.LastStatistics)
	}
	active := h.activeJobs()
	if len(active) != 1 || active[0].Annotations[annotationReplicationDestination] != "pg-backups-dr" {
		t.Fatalf("want the second bucket's Job next, got %+v", active)
	}

	h.now = h.now.Add(time.Minute)
	h.finishJob(active[0].Name, true, "", replTestSuccessMessage)
	res := h.reconcile()
	repl = h.get()
	if repl.Status.CurrentRun != nil || repl.Status.LastRun == nil || repl.Status.LastRun.Result != garagev1beta1.ReplicationResultSucceeded {
		t.Fatalf("run should be complete: current=%+v last=%+v", repl.Status.CurrentRun, repl.Status.LastRun)
	}
	if repl.Status.LastSuccessfulSyncTime == nil || !repl.Status.LastSuccessfulSyncTime.Time.Equal(h.now) {
		t.Fatalf("lastSuccessfulSyncTime = %v, want %v", repl.Status.LastSuccessfulSyncTime, h.now)
	}
	if !meta.IsStatusConditionTrue(repl.Status.Conditions, ConditionReplicationSynced) || repl.Status.Phase != garagev1beta1.ReplicationPhaseIdle {
		t.Fatalf("want Synced=True and Idle, got phase=%s conditions=%+v", repl.Status.Phase, repl.Status.Conditions)
	}
	wantNext := time.Date(2026, 11, 9, 12, 15, 0, 0, time.UTC)
	if repl.Status.NextSyncTime == nil || !repl.Status.NextSyncTime.Time.Equal(wantNext) {
		t.Fatalf("nextSyncTime = %v, want %v", repl.Status.NextSyncTime, wantNext)
	}
	if res.RequeueAfter != wantNext.Sub(h.now) {
		t.Fatalf("requeue %v, want until next sync %v", res.RequeueAfter, wantNext.Sub(h.now))
	}
}

func completeRun(t *testing.T, h *replicationHarness, message string, succeeded bool) {
	t.Helper()
	for i := 0; i < 10; i++ {
		h.reconcile()
		active := h.activeJobs()
		if len(active) == 0 {
			if h.get().Status.CurrentRun == nil {
				return
			}
			continue
		}
		for _, j := range active {
			h.finishJob(j.Name, succeeded, "", message)
		}
	}
	t.Fatal("run did not complete")
}

func TestReplicationScheduledRunsCollapseAndNeverOverlap(t *testing.T) {
	h := newReplicationHarness(t, replicationFixture())
	completeRun(t, h, replTestSuccessMessage, true)

	h.now = h.now.Add(10 * time.Minute)
	h.reconcile()
	if len(h.activeJobs()) != 0 {
		t.Fatal("no run is due before the schedule")
	}

	// Three schedule ticks pass while the operator is down: one run.
	h.now = h.now.Add(50 * time.Minute)
	h.reconcile()
	repl := h.get()
	if repl.Status.CurrentRun == nil || repl.Status.CurrentRun.Reason != garagev1beta1.ReplicationRunScheduled {
		t.Fatalf("want a Scheduled run, got %+v", repl.Status.CurrentRun)
	}
	firstRun := repl.Status.CurrentRun.ID

	// A long run passes the next tick: no second run starts meanwhile.
	h.now = h.now.Add(20 * time.Minute)
	h.reconcile()
	if got := h.get().Status.CurrentRun.ID; got != firstRun {
		t.Fatalf("runs overlapped: %s then %s", firstRun, got)
	}
	if len(h.activeJobs()) != 1 {
		t.Fatalf("want exactly one active Job, got %d", len(h.activeJobs()))
	}
}

func TestReplicationSuspendStopsScheduleButTriggerStillRuns(t *testing.T) {
	h := newReplicationHarness(t, replicationFixture())
	completeRun(t, h, replTestSuccessMessage, true)
	h.update(func(r *garagev1beta1.GarageReplication) { r.Spec.Suspend = true })

	h.now = h.now.Add(2 * time.Hour)
	h.reconcile()
	repl := h.get()
	if repl.Status.CurrentRun != nil || repl.Status.Phase != garagev1beta1.ReplicationPhaseSuspended || repl.Status.NextSyncTime != nil {
		t.Fatalf("suspended replication must not run: phase=%s run=%+v next=%v", repl.Status.Phase, repl.Status.CurrentRun, repl.Status.NextSyncTime)
	}
	if !meta.IsStatusConditionTrue(repl.Status.Conditions, ConditionReplicationSuspended) {
		t.Fatal("Suspended condition should be True")
	}

	h.trigger("final-sync-1")
	h.reconcile()
	repl = h.get()
	if repl.Status.CurrentRun == nil || repl.Status.CurrentRun.Reason != garagev1beta1.ReplicationRunTriggered {
		t.Fatalf("trigger should start a run even while suspended, got %+v", repl.Status.CurrentRun)
	}
	if _, ok := repl.Annotations[AnnotationTriggerSync]; ok {
		t.Fatal("trigger annotation should be consumed")
	}
	if repl.Status.LastOperation == nil || repl.Status.LastOperation.Type != "TriggerSync" || !repl.Status.LastOperation.Succeeded {
		t.Fatalf("lastOperation not recorded: %+v", repl.Status.LastOperation)
	}

	// Resume: the schedule takes over again.
	completeRun(t, h, replTestSuccessMessage, true)
	h.update(func(r *garagev1beta1.GarageReplication) { r.Spec.Suspend = false })
	h.reconcile()
	if h.get().Status.NextSyncTime == nil {
		t.Fatal("resumed replication should have a next sync time")
	}
}

func TestReplicationTriggerDuringRunWaitsForIt(t *testing.T) {
	h := newReplicationHarness(t, replicationFixture())
	h.reconcile()
	initial := h.get().Status.CurrentRun.ID
	h.trigger("after-freeze")
	h.reconcile()
	repl := h.get()
	if repl.Status.CurrentRun.ID != initial || repl.Annotations[AnnotationTriggerSync] != "after-freeze" {
		t.Fatal("a trigger must wait for the active run and stay pending")
	}
	completeRun(t, h, replTestSuccessMessage, true)
	repl = h.get()
	if repl.Status.LastRun == nil || repl.Status.LastRun.Reason != garagev1beta1.ReplicationRunTriggered || repl.Status.LastRun.Trigger != "after-freeze" {
		t.Fatalf("the triggered run should have run after the initial one, last run %+v", repl.Status.LastRun)
	}
}

func TestReplicationFailureIsReportedWithFixedReason(t *testing.T) {
	h := newReplicationHarness(t, replicationFixture())
	completeRun(t, h, "garage-replication/v1 exit=1 reason=AuthFailed verify= differences= stats=1 transfers=0 bytes=0 checks=0 deletes=0 errors=1 elapsedTime=0.1", false)
	repl := h.get()
	b := bucketStatus(t, repl, "medias")
	if b.LastResult != garagev1beta1.ReplicationResultFailed || b.LastError != garagev1beta1.ReplicationFailureAuthFailed || b.Hold != "" {
		t.Fatalf("want Failed/AuthFailed without hold, got %+v", b)
	}
	if repl.Status.Phase != garagev1beta1.ReplicationPhaseFailed || repl.Status.LastSuccessfulSyncTime != nil {
		t.Fatalf("phase=%s lastSuccess=%v", repl.Status.Phase, repl.Status.LastSuccessfulSyncTime)
	}
	synced := meta.FindStatusCondition(repl.Status.Conditions, ConditionReplicationSynced)
	if synced == nil || synced.Status != metav1.ConditionFalse || synced.Reason != "SyncFailed" {
		t.Fatalf("Synced condition %+v", synced)
	}

	// A Pod killed before writing its message yields no invented statistics.
	h.now = h.now.Add(time.Hour)
	h.reconcile()
	active := h.activeJobs()
	h.finishJob(active[0].Name, false, batchv1.JobReasonDeadlineExceeded, "")
	h.reconcile()
	b = bucketStatus(t, h.get(), "medias")
	if b.LastError != garagev1beta1.ReplicationFailureDeadlineExceeded || b.LastStatistics != nil {
		t.Fatalf("want DeadlineExceeded without statistics, got %+v", b)
	}
}

func TestReplicationFirstMirrorRunWaitsForTrigger(t *testing.T) {
	h := newReplicationHarness(t, mirrorFixture(10))
	h.reconcile()
	if len(h.jobs()) != 0 {
		t.Fatal("a new Mirror replication must not run before a trigger")
	}
	repl := h.get()
	if b := bucketStatus(t, repl, "medias"); b.Hold != garagev1beta1.ReplicationHoldAwaitingTrigger {
		t.Fatalf("want hold AwaitingTrigger, got %+v", b)
	}
	if c := meta.FindStatusCondition(repl.Status.Conditions, ConditionReplicationSynced); c == nil || c.Reason != "AwaitingTrigger" {
		t.Fatalf("want Synced reason AwaitingTrigger, got %+v", c)
	}

	// Schedule ticks and spec edits do not start it.
	h.now = h.now.Add(time.Hour)
	h.update(func(r *garagev1beta1.GarageReplication) { r.Spec.Mirror.MaxDeletes = 20 })
	h.reconcile()
	if len(h.jobs()) != 0 {
		t.Fatal("only a trigger may start the first Mirror run")
	}

	h.trigger("first-mirror")
	completeRun(t, h, replTestSuccessMessage, true)
	b := bucketStatus(t, h.get(), "medias")
	if b.Hold != "" || b.LastMode != garagev1beta1.ReplicationModeMirror || b.LastResult != garagev1beta1.ReplicationResultSucceeded {
		t.Fatalf("triggered Mirror run not recorded: %+v", b)
	}

	// Later scheduled Mirror runs need no trigger.
	h.now = h.now.Add(time.Hour)
	h.reconcile()
	if len(h.activeJobs()) != 1 {
		t.Fatal("a scheduled Mirror run should start once a Mirror run happened")
	}
}

func TestReplicationSwitchToMirrorWaitsForTrigger(t *testing.T) {
	repl := replicationFixture()
	repl.Spec.Buckets = repl.Spec.Buckets[:1]
	h := newReplicationHarness(t, repl)
	completeRun(t, h, replTestSuccessMessage, true)

	h.update(func(r *garagev1beta1.GarageReplication) {
		r.Spec.Mode = garagev1beta1.ReplicationModeMirror
		r.Spec.Mirror = &garagev1beta1.ReplicationMirrorConfig{MaxDeletes: 10}
	})
	h.now = h.now.Add(time.Hour)
	h.reconcile()
	if len(h.activeJobs()) != 0 || bucketStatus(t, h.get(), "medias").Hold != garagev1beta1.ReplicationHoldAwaitingTrigger {
		t.Fatal("switching from Copy to Mirror must wait for a trigger")
	}

	// Going back to Copy drops the hold: Copy never deletes.
	h.update(func(r *garagev1beta1.GarageReplication) {
		r.Spec.Mode = garagev1beta1.ReplicationModeCopy
		r.Spec.Mirror = nil
	})
	h.reconcile()
	if bucketStatus(t, h.get(), "medias").Hold != "" {
		t.Fatal("AwaitingTrigger must not hold a Copy bucket")
	}
}

func TestReplicationSafetyHoldIsReleasedOnlyByTrigger(t *testing.T) {
	h := newReplicationHarness(t, mirrorFixture(10))
	h.trigger("first-mirror")
	completeRun(t, h, replTestMaxDeletesMessage, false)
	b := bucketStatus(t, h.get(), "medias")
	if b.Hold != garagev1beta1.ReplicationHoldMaxDeletesExceeded || b.LastError != garagev1beta1.ReplicationFailureMaxDeletesExceeded {
		t.Fatalf("want hold MaxDeletesExceeded, got %+v", b)
	}

	h.now = h.now.Add(time.Hour)
	h.reconcile()
	if len(h.activeJobs()) != 0 {
		t.Fatal("a scheduled run must skip a held bucket")
	}
	got := h.get()
	if got.Status.CurrentRun != nil || meta.FindStatusCondition(got.Status.Conditions, ConditionReplicationSynced).Reason != "SafetyHold" {
		t.Fatalf("want SafetyHold, got %+v", got.Status.Conditions)
	}

	// Raising the cap is a spec edit: it must not release the hold, and
	// neither must an unrelated edit.
	h.update(func(r *garagev1beta1.GarageReplication) { r.Spec.Mirror.MaxDeletes = 1000 })
	h.update(func(r *garagev1beta1.GarageReplication) {
		r.Spec.Transfer = &garagev1beta1.ReplicationTransferConfig{BandwidthLimit: "10M"}
	})
	h.now = h.now.Add(time.Hour)
	h.reconcile()
	if len(h.activeJobs()) != 0 || bucketStatus(t, h.get(), "medias").Hold != garagev1beta1.ReplicationHoldMaxDeletesExceeded {
		t.Fatal("a spec edit must not release a safety hold")
	}

	h.trigger("checked-both-sides")
	h.reconcile()
	if len(h.activeJobs()) != 1 || bucketStatus(t, h.get(), "medias").Hold != "" {
		t.Fatal("trigger-sync should release the hold and run the bucket")
	}
}

func TestReplicationModeDowngradeCancelsDestructiveJob(t *testing.T) {
	h := newReplicationHarness(t, mirrorFixture(10))
	h.trigger("first-mirror")
	h.reconcile()
	running := h.activeJobs()[0].Name

	h.update(func(r *garagev1beta1.GarageReplication) {
		r.Spec.Mode = garagev1beta1.ReplicationModeCopy
		r.Spec.Mirror = nil
	})
	h.reconcile()
	for _, j := range h.jobs() {
		if j.Name == running {
			t.Fatal("the Mirror Job should have been deleted after switching to Copy")
		}
	}
	b := bucketStatus(t, h.get(), "medias")
	if b.LastResult != garagev1beta1.ReplicationResultCancelled || b.LastMode != garagev1beta1.ReplicationModeMirror {
		t.Fatalf("want Cancelled Mirror Job, got %+v", b)
	}
}

func TestReplicationNonDestructiveSpecChangeLetsJobFinish(t *testing.T) {
	h := newReplicationHarness(t, replicationFixture())
	h.reconcile()
	running := h.activeJobs()[0].Name
	h.update(func(r *garagev1beta1.GarageReplication) {
		r.Spec.Transfer = &garagev1beta1.ReplicationTransferConfig{Concurrency: 16}
	})
	h.reconcile()
	if active := h.activeJobs(); len(active) != 1 || active[0].Name != running {
		t.Fatal("a non-destructive change must not cancel the running Job")
	}
}

func TestReplicationRemovedOrRepointedBucketCancelsItsJob(t *testing.T) {
	h := newReplicationHarness(t, replicationFixture())
	h.reconcile()
	h.update(func(r *garagev1beta1.GarageReplication) { r.Spec.Buckets = r.Spec.Buckets[1:] })
	h.reconcile()
	for _, j := range h.activeJobs() {
		if j.Annotations[annotationReplicationDestination] == "medias" {
			t.Fatal("Job of a removed bucket should be deleted")
		}
	}
	if len(h.get().Status.Buckets) != 1 {
		t.Fatal("status should only list spec buckets")
	}

	h.reconcile()
	active := h.activeJobs()
	if len(active) != 1 || active[0].Annotations[annotationReplicationSource] != "pg-backups" {
		t.Fatalf("want the pg-backups Job, got %+v", active)
	}
	h.update(func(r *garagev1beta1.GarageReplication) { r.Spec.Buckets[0].Source = "pg-backups-v2" })
	h.reconcile()
	for _, j := range h.activeJobs() {
		if j.Name == active[0].Name {
			t.Fatal("a Job copying the old source into the destination should be deleted")
		}
	}
	if b := bucketStatus(t, h.get(), "pg-backups-dr"); b.Source != "pg-backups-v2" || b.LastResult != garagev1beta1.ReplicationResultCancelled {
		t.Fatalf("status should follow the new source and record the cancel, got %+v", b)
	}
}

func TestReplicationManuallyDeletedJobIsNotRecreated(t *testing.T) {
	h := newReplicationHarness(t, replicationFixture())
	h.reconcile()
	job := h.activeJobs()[0]
	if err := h.c.Delete(context.Background(), &job); err != nil {
		t.Fatal(err)
	}
	h.reconcile()
	for _, j := range h.jobs() {
		if j.Name == job.Name {
			t.Fatal("a Job someone deleted must not be recreated")
		}
	}
	if b := bucketStatus(t, h.get(), job.Annotations[annotationReplicationDestination]); b.LastResult != garagev1beta1.ReplicationResultCancelled {
		t.Fatalf("want Cancelled, got %+v", b)
	}
}

func TestReplicationMissingSecretBlocksJobs(t *testing.T) {
	repl := replicationFixture()
	repl.Spec.Destination.CredentialsSecretRef.Name = "missing"
	h := newReplicationHarness(t, repl)
	res := h.reconcile()
	if len(h.jobs()) != 0 {
		t.Fatal("no Job without credentials")
	}
	got := h.get()
	ready := readyCondition(t, got)
	if ready.Status != metav1.ConditionFalse || ready.Reason != "SecretNotFound" || got.Status.Phase != garagev1beta1.ReplicationPhasePending {
		t.Fatalf("want Ready=False/SecretNotFound and Pending, got %+v phase=%s", ready, got.Status.Phase)
	}
	if res.RequeueAfter != replicationNotReadyRequeue {
		t.Fatalf("requeue %v", res.RequeueAfter)
	}
	if strings.Contains(ready.Message, replTestSecretKey) {
		t.Fatal("secret material leaked into status")
	}
}

func TestReplicationCredentialsSecretMustOptIn(t *testing.T) {
	// A GarageKey-generated Secret without the label is refused too: being
	// generated for a key does not make it replication credentials.
	keySecret := replicationTestSecret("other-app-key", false)
	keySecret.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: garagev1beta1.GroupVersion.String(), Kind: "GarageKey", Name: "other-app", UID: "key-uid", Controller: ptr.To(true),
	}}
	repl := replicationFixture()
	repl.Spec.Source.CredentialsSecretRef.Name = keySecret.Name
	h := newReplicationHarness(t, repl, keySecret)
	h.reconcile()
	if len(h.jobs()) != 0 {
		t.Fatal("no Job may use a Secret that did not opt in")
	}
	ready := readyCondition(t, h.get())
	if ready.Reason != ReplicationReasonCredentialsNotAllowed || !strings.Contains(ready.Message, garagev1beta1.LabelReplicationCredentials) {
		t.Fatalf("want CredentialsNotAllowed naming the label, got %+v", ready)
	}

	keySecret.Labels = map[string]string{garagev1beta1.LabelReplicationCredentials: "true"}
	if err := h.c.Update(context.Background(), keySecret); err != nil {
		t.Fatal(err)
	}
	h.reconcile()
	if len(h.jobs()) != 1 {
		t.Fatal("an opted-in Secret should be used")
	}
}

func TestReplicationCABundleComesFromConfigMap(t *testing.T) {
	repl := replicationFixture()
	repl.Spec.Destination.Endpoint.CABundleRef = &garagev1beta1.ReplicationCABundleRef{Name: "dr-ca"}
	h := newReplicationHarness(t, repl)
	h.reconcile()
	if ready := readyCondition(t, h.get()); ready.Reason != "CABundleNotFound" {
		t.Fatalf("want CABundleNotFound, got %+v", ready)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "dr-ca", Namespace: replTestNamespace},
		Data:       map[string]string{garagev1beta1.ReplicationDefaultCABundleKey: "-----BEGIN CERTIFICATE-----"},
	}
	if err := h.c.Create(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
	h.reconcile()
	jobs := h.jobs()
	if len(jobs) != 1 {
		t.Fatalf("want a Job once the CA exists, got %d", len(jobs))
	}
	vols := jobs[0].Spec.Template.Spec.Volumes
	found := false
	for _, v := range vols {
		if v.Secret != nil {
			t.Fatal("no Secret volume may be mounted for a CA")
		}
		if v.ConfigMap != nil && v.ConfigMap.Name == "dr-ca" && v.ConfigMap.Items[0].Key == garagev1beta1.ReplicationDefaultCABundleKey {
			found = true
		}
	}
	if !found {
		t.Fatalf("CA ConfigMap not mounted: %+v", vols)
	}
}

func TestReplicationDestinationConflictComparesResolvedURLs(t *testing.T) {
	// The older object writes "medias" on the destination cluster through a
	// clusterRef; the newer one names the same cluster by URL.
	dr := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "garage", Namespace: replTestNamespace},
		Spec:       garagev1beta2.GarageClusterSpec{S3API: &garagev1beta2.S3APIConfig{BindPort: 3900}},
	}
	older := replicationFixture()
	older.Name, older.UID = "older", "older-uid"
	older.CreationTimestamp = metav1.NewTime(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	older.Spec.Destination = garagev1beta1.ReplicationEndpoint{
		ClusterRef:           &garagev1beta1.ClusterReference{Name: "garage"},
		CredentialsSecretRef: garagev1beta1.ReplicationCredentialsRef{Name: replTestDstSecret},
	}
	older.Spec.Buckets = older.Spec.Buckets[:1]
	repl := replicationFixture()
	repl.Spec.Destination.Endpoint.URL = "HTTP://garage.dr.svc.cluster.local:3900/"
	h := newReplicationHarness(t, repl, dr, older)
	h.reconcile()
	if len(h.jobs()) != 0 {
		t.Fatal("the newer GarageReplication must not write a taken destination bucket")
	}
	ready := readyCondition(t, h.get())
	if ready.Reason != ReplicationReasonDestinationConflict || !strings.Contains(ready.Message, `"older"`) {
		t.Fatalf("want DestinationConflict naming the same-namespace owner, got %+v", ready)
	}

	// Another namespace's owner is not named.
	h2 := newReplicationHarness(t, replicationFixture(), func() client.Object {
		o := replicationFixture()
		o.Name, o.Namespace, o.UID = "secret-project", "elsewhere", "other-uid"
		o.CreationTimestamp = older.CreationTimestamp
		return o
	}())
	h2.reconcile()
	ready = readyCondition(t, h2.get())
	if ready.Reason != ReplicationReasonDestinationConflict || strings.Contains(ready.Message, "secret-project") || strings.Contains(ready.Message, "elsewhere") {
		t.Fatalf("want a DestinationConflict that does not reveal the other namespace, got %+v", ready)
	}
}

func TestReplicationClusterRefResolvesEndpointAndRequiresGrant(t *testing.T) {
	cluster := &garagev1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "prod", Namespace: "storage"},
		Spec:       garagev1beta2.GarageClusterSpec{S3API: &garagev1beta2.S3APIConfig{BindPort: 3900, Region: "eu"}},
	}
	repl := replicationFixture()
	repl.Spec.Source.Endpoint = nil
	repl.Spec.Source.ClusterRef = &garagev1beta1.ClusterReference{Name: "prod", Namespace: "storage"}
	h := newReplicationHarness(t, repl, cluster)
	h.reconcile()
	if ready := readyCondition(t, h.get()); ready.Reason != "ReferenceNotGranted" || len(h.jobs()) != 0 {
		t.Fatalf("cross-namespace clusterRef needs a grant, got %+v", ready)
	}

	grant := &garagev1beta1.GarageReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-dr", Namespace: "storage"},
		Spec: garagev1beta1.GarageReferenceGrantSpec{
			From: []garagev1beta1.ReferenceGrantFrom{{Kind: kindGarageReplication, Namespace: replTestNamespace}},
			To:   []garagev1beta1.ReferenceGrantTo{{Kind: kindGarageCluster, Name: "prod"}},
		},
	}
	if err := h.c.Create(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	h.reconcile()
	jobs := h.jobs()
	if len(jobs) != 1 {
		t.Fatalf("want a Job once granted, got %d", len(jobs))
	}
	env := map[string]string{}
	for _, e := range jobs[0].Spec.Template.Spec.Containers[0].Env {
		env[e.Name] = e.Value
	}
	if env["RCLONE_CONFIG_SRC_ENDPOINT"] != "http://prod.storage.svc.cluster.local:3900" || env["RCLONE_CONFIG_SRC_REGION"] != "eu" {
		t.Fatalf("source endpoint not resolved from the GarageCluster: %q %q", env["RCLONE_CONFIG_SRC_ENDPOINT"], env["RCLONE_CONFIG_SRC_REGION"])
	}
}

func TestReplicationPrunesRecordedJobHistory(t *testing.T) {
	repl := replicationFixture()
	repl.Spec.Buckets = repl.Spec.Buckets[:1]
	h := newReplicationHarness(t, repl)
	for i := 0; i < 4; i++ {
		completeRun(t, h, replTestSuccessMessage, true)
		h.now = h.now.Add(15 * time.Minute)
	}
	h.reconcile()
	finished := 0
	for _, j := range h.jobs() {
		if done, _, _ := replicationJobFinished(&j); done {
			finished++
		}
	}
	if finished != 1 {
		t.Fatalf("successfulJobsHistoryLimit defaults to 1, %d finished Jobs kept", finished)
	}
}

func TestReplicationJobCarriesNoSecretMaterial(t *testing.T) {
	repl := mirrorFixture(100)
	repl.Spec.Mirror.MaxDeleteSize = "10G"
	repl.Spec.Transfer = &garagev1beta1.ReplicationTransferConfig{BandwidthLimit: "1024"}
	repl.Spec.Destination.Endpoint.CABundleRef = &garagev1beta1.ReplicationCABundleRef{Name: "dr-ca", Key: "bundle.pem"}
	job := buildReplicationJob(replicationJobInput{
		Replication: repl, Bucket: repl.Spec.Buckets[0], RunID: replicationRunID(time.Unix(1762689600, 0)),
		SpecHash: "abc", Image: DefaultReplicationImage,
		Source:      resolvedReplicationEndpoint{URL: "https://s3.prod.example.com", Region: "garage", Credentials: repl.Spec.Source.CredentialsSecretRef},
		Destination: resolvedReplicationEndpoint{URL: replTestDstURL, Region: "dr", Credentials: repl.Spec.Destination.CredentialsSecretRef, CABundle: repl.Spec.Destination.Endpoint.CABundleRef},
	})
	raw, _ := json.Marshal(job)
	if strings.Contains(string(raw), replTestSecretKey) || strings.Contains(string(raw), replTestSecretID) {
		t.Fatal("Job must reference credentials, never embed them")
	}
	c := job.Spec.Template.Spec.Containers[0]
	refs := 0
	env := map[string]string{}
	for _, e := range c.Env {
		env[e.Name] = e.Value
		if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
			refs++
		}
	}
	if refs != 4 {
		t.Fatalf("want 4 secretKeyRef env vars (2 per side), got %d", refs)
	}
	want := map[string]string{
		"GR_MODE": "Mirror", "GR_MAX_DELETES": "100", "GR_MAX_DELETE_SIZE": "10G",
		// rclone reads a bare number as KiB; the API means bytes.
		"GR_BWLIMIT":   "1024B",
		"GR_CA_FILES":  "/etc/garage-replication/ca/destination/ca.crt",
		"GR_TRANSFERS": "4", "GR_CHECKERS": "8", "GR_VERIFY": "None",
	}
	for k, v := range want {
		if env[k] != v {
			t.Fatalf("%s = %q, want %q (env %+v)", k, env[k], v, env)
		}
	}
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.Name == "ca-destination" && (v.ConfigMap == nil || v.ConfigMap.Items[0].Key != "bundle.pem") {
			t.Fatalf("CA volume %+v", v)
		}
	}
	sc := c.SecurityContext
	if sc == nil || !*sc.ReadOnlyRootFilesystem || *sc.AllowPrivilegeEscalation || !*job.Spec.Template.Spec.SecurityContext.RunAsNonRoot || *job.Spec.Template.Spec.AutomountServiceAccountToken {
		t.Fatal("replication Pods must run locked down")
	}
	if p := job.Spec.PodFailurePolicy; p == nil || len(p.Rules) == 0 || p.Rules[0].Action != batchv1.PodFailurePolicyActionFailJob {
		t.Fatal("safety-guard exit codes must fail the Job without retry")
	}
	if len(job.Name) > 63 {
		t.Fatalf("Job name %q too long", job.Name)
	}
}

func TestReplicationJobNameIsBoundedAndDeterministic(t *testing.T) {
	long := strings.Repeat("a", 253)
	b := garagev1beta1.ReplicationBucket{Source: "medias", Destination: "medias"}
	n1 := replicationJobName(long, "t2b5wg", b)
	if n1 != replicationJobName(long, "t2b5wg", b) || len(n1) > 63 {
		t.Fatalf("name %q", n1)
	}
	if n1 == replicationJobName(long, "t2b5wg", garagev1beta1.ReplicationBucket{Source: "medias", Destination: "other"}) {
		t.Fatal("different destinations must get different Jobs")
	}
	if !replicationRunIDLess("", "t2b5wg") || !replicationRunIDLess("zzzzzz", "1000000") {
		t.Fatal("run IDs must order by time, not by string")
	}
}

func TestParseReplicationTermination(t *testing.T) {
	got, ok := parseReplicationTermination("garage-replication/v1 exit=1 reason=VerificationFailed verify=Failed differences=3 stats=1 transfers=1 bytes=2 checks=3 deletes=4 errors=6 elapsedTime=7.4")
	if !ok || got.ExitCode != 1 || got.Reason != string(garagev1beta1.ReplicationFailureVerificationFailed) || got.Verification != "Failed" {
		t.Fatalf("got %+v", got)
	}
	s := got.Stats
	if s.Transfers != 1 || s.Bytes != 2 || s.Checks != 3 || s.Deletes != 4 || s.Errors != 6 || s.ElapsedSeconds != 7 || s.Differences == nil || *s.Differences != 3 {
		t.Fatalf("stats %+v", s)
	}
	if got, ok := parseReplicationTermination("garage-replication/v1 exit=143 reason=Terminated verify= differences= stats=0"); !ok || got.Stats != nil {
		t.Fatalf("no stats must stay nil, got %+v", got)
	}
	for _, bad := range []string{"", "panic: boom", "garage-replication/v1 exit=abc"} {
		if _, ok := parseReplicationTermination(bad); ok {
			t.Fatalf("%q should not parse", bad)
		}
	}
	failed := &batchv1.Job{Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}}}
	pod := func(msg string) []corev1.Pod {
		return []corev1.Pod{{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name: replicationContainerName, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Message: msg}},
		}}}}}
	}
	for msg, want := range map[string]garagev1beta1.ReplicationFailureReason{
		"garage-replication/v1 exit=1 reason=<script> stats=0":     garagev1beta1.ReplicationFailureTransferErrors,
		"garage-replication/v1 exit=143 reason=Terminated stats=0": garagev1beta1.ReplicationFailureUnknown,
		"garage-replication/v1 exit=65 reason=MaxDeletesExceeded":  garagev1beta1.ReplicationFailureMaxDeletesExceeded,
	} {
		if out := summarizeReplicationJob(failed, pod(msg)); out.Reason != want {
			t.Fatalf("%q: reason %q, want %q", msg, out.Reason, want)
		}
	}
	if replicationSafetyHold(garagev1beta1.ReplicationFailureAuthFailed) != "" ||
		replicationSafetyHold(garagev1beta1.ReplicationFailureSourceEmpty) != garagev1beta1.ReplicationHoldSourceEmpty {
		t.Fatal("only the safety guards hold a bucket")
	}
}
