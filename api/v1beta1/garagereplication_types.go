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

package v1beta1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GarageReplicationSpec defines the desired state of GarageReplication.
//
// GarageReplication copies objects between two independent Garage clusters
// through their S3 APIs, for replication and migration. It is not a backup:
// there are no point-in-time snapshots and no restore, and in mode Mirror a
// deletion or an overwrite on the source reaches the destination on the next
// run. Each run executes one Kubernetes Job per bucket in the
// GarageReplication's namespace, so the Jobs need network access to both S3
// endpoints. Only objects (and their user metadata) are copied: buckets, keys,
// permissions, quotas, website and lifecycle configuration are not. Deleting a
// GarageReplication never deletes object data on either side.
// +kubebuilder:validation:XValidation:rule="has(self.mirror) == (has(self.mode) && self.mode == 'Mirror')",message="mirror must be set if and only if mode is Mirror"
// +kubebuilder:validation:XValidation:rule="!(has(self.source.endpoint) && has(self.destination.endpoint) && self.source.endpoint.url.lowerAscii() == self.destination.endpoint.url.lowerAscii()) || self.buckets.all(b, b.source != b.destination)",message="a bucket cannot be replicated onto itself: source and destination are the same endpoint"
type GarageReplicationSpec struct {
	// Source is the cluster objects are read from. Its credentials only need
	// read permission on the source buckets.
	// +required
	Source ReplicationEndpoint `json:"source"`

	// Destination is the cluster objects are written to. Its credentials need
	// read and write permission on the destination buckets. Destination
	// buckets must already exist: replication never creates buckets. A
	// destination bucket can be written by only one GarageReplication.
	// +required
	Destination ReplicationEndpoint `json:"destination"`

	// Buckets lists the buckets to replicate, keyed by destination bucket.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=50
	// +listType=map
	// +listMapKey=destination
	// +required
	Buckets []ReplicationBucket `json:"buckets"`

	// Schedule is a cron expression (standard 5-field syntax, descriptors
	// such as @hourly, optional CRON_TZ= prefix; UTC otherwise). Without a
	// schedule, runs happen only through the garage.rajsingh.info/trigger-sync
	// annotation (one-shot mode, e.g. for migrations).
	// +kubebuilder:validation:MaxLength=128
	// +optional
	Schedule string `json:"schedule,omitempty"`

	// Suspend stops starting new runs. A run already in progress finishes;
	// delete its Jobs to stop it immediately.
	// +optional
	Suspend bool `json:"suspend,omitempty"`

	// Mode controls whether changes on the source can remove data on the
	// destination.
	//   - Copy: copy new and changed objects. Source deletions are not
	//     propagated. Changed objects are overwritten on the destination.
	//   - Mirror: the destination reflects the source, including deletions,
	//     capped by mirror.maxDeletes per bucket and run. The first run waits
	//     for the trigger-sync annotation.
	// +kubebuilder:validation:Enum=Copy;Mirror
	// +kubebuilder:default=Copy
	// +optional
	Mode ReplicationMode `json:"mode,omitempty"`

	// Mirror configures mode Mirror. Required when mode is Mirror and
	// rejected otherwise.
	// +optional
	Mirror *ReplicationMirrorConfig `json:"mirror,omitempty"`

	// Verification runs a comparison of source and destination after each
	// successful copy. Check compares sizes and MD5 hashes (size only for
	// multipart objects without a stored MD5) and fails the run on any
	// difference.
	// +kubebuilder:validation:Enum=None;Check
	// +kubebuilder:default=None
	// +optional
	Verification ReplicationVerification `json:"verification,omitempty"`

	// Transfer tunes the copy.
	// +optional
	Transfer *ReplicationTransferConfig `json:"transfer,omitempty"`

	// Retry bounds retries and duration of each per-bucket Job.
	// +optional
	Retry *ReplicationRetryConfig `json:"retry,omitempty"`

	// Resources for the replication container.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// PodTemplate customizes the replication Pods.
	// +optional
	PodTemplate *ReplicationPodTemplate `json:"podTemplate,omitempty"`

	// SuccessfulJobsHistoryLimit is the number of finished successful Jobs to
	// keep.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=50
	// +kubebuilder:default=1
	// +optional
	SuccessfulJobsHistoryLimit *int32 `json:"successfulJobsHistoryLimit,omitempty"`

	// FailedJobsHistoryLimit is the number of finished failed Jobs to keep.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=50
	// +kubebuilder:default=3
	// +optional
	FailedJobsHistoryLimit *int32 `json:"failedJobsHistoryLimit,omitempty"`
}

// ReplicationMode selects how deletions and overwrites propagate.
type ReplicationMode string

const (
	// ReplicationModeCopy never deletes destination objects.
	ReplicationModeCopy ReplicationMode = "Copy"
	// ReplicationModeMirror propagates source deletions to the destination.
	ReplicationModeMirror ReplicationMode = "Mirror"
)

// ReplicationVerification selects the post-copy verification.
type ReplicationVerification string

const (
	// ReplicationVerificationNone skips verification.
	ReplicationVerificationNone ReplicationVerification = "None"
	// ReplicationVerificationCheck compares source and destination after the copy.
	ReplicationVerificationCheck ReplicationVerification = "Check"
)

// LabelReplicationCredentials opts a Secret in to being used as
// GarageReplication credentials. Secrets generated for a GarageKey are
// accepted without it.
const LabelReplicationCredentials = AnnotationPrefix + "replication-credentials"

// ReplicationEndpoint identifies one side of a replication. Exactly one of
// clusterRef or endpoint must be set.
// +kubebuilder:validation:XValidation:rule="has(self.clusterRef) != has(self.endpoint)",message="exactly one of clusterRef or endpoint must be set"
// +kubebuilder:validation:XValidation:rule="!has(self.clusterRef) || !has(self.clusterRef.kubeConfigSecretRef)",message="clusterRef.kubeConfigSecretRef is not supported"
type ReplicationEndpoint struct {
	// ClusterRef references a GarageCluster (operator-managed or a
	// management handle). The S3 endpoint and region are resolved from it.
	// A cross-namespace reference requires a GarageReferenceGrant in the
	// cluster's namespace that allows kind GarageReplication.
	// +optional
	ClusterRef *ClusterReference `json:"clusterRef,omitempty"`

	// Endpoint is an S3 endpoint of any Garage cluster, inside or outside
	// Kubernetes.
	// +optional
	Endpoint *ReplicationS3Endpoint `json:"endpoint,omitempty"`

	// CredentialsSecretRef references a Secret in the GarageReplication's
	// namespace holding an S3 access key. The Secret must opt in: either it
	// is the Secret generated for a GarageKey, or it carries the label
	// garage.rajsingh.info/replication-credentials: "true". The access key ID
	// is sent to the endpoint, so without this opt-in the right to create a
	// GarageReplication would amount to reading any Secret. The default data
	// keys match the Secret generated for a GarageKey.
	// +required
	CredentialsSecretRef ReplicationCredentialsRef `json:"credentialsSecretRef"`
}

// ReplicationS3Endpoint is an explicit S3 endpoint.
type ReplicationS3Endpoint struct {
	// URL of the S3 API: scheme and host (with an optional port) only, e.g.
	// https://s3.example.com or http://garage.ns.svc:3900. Buckets are
	// addressed path-style below it, so it has no path, query, fragment or
	// credentials.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^https?://[^\s/?#@]+/?$`
	// +required
	URL string `json:"url"`

	// Region is the Garage s3_region used for request signing.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_.-]+$`
	// +kubebuilder:default=garage
	// +optional
	Region string `json:"region,omitempty"`

	// CABundleRef references a ConfigMap holding a PEM CA bundle used, in
	// addition to the system trust store, to verify the endpoint's TLS
	// certificate.
	// +optional
	CABundleRef *ReplicationCABundleRef `json:"caBundleRef,omitempty"`
}

// ReplicationCABundleRef selects a key of a ConfigMap in the
// GarageReplication's namespace. A CA bundle is public, so it is read from a
// ConfigMap only.
type ReplicationCABundleRef struct {
	// Name of the ConfigMap.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	// +required
	Name string `json:"name"`

	// Key of the ConfigMap holding the PEM bundle.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	// +kubebuilder:default="ca.crt"
	// +optional
	Key string `json:"key,omitempty"`
}

// ReplicationCredentialsRef references a Secret holding an S3 access key.
// +kubebuilder:validation:XValidation:rule="(has(self.accessKeyIdKey) ? self.accessKeyIdKey : 'access-key-id') != (has(self.secretAccessKeyKey) ? self.secretAccessKeyKey : 'secret-access-key')",message="accessKeyIdKey and secretAccessKeyKey must be different"
type ReplicationCredentialsRef struct {
	// Name of the Secret in the GarageReplication's namespace.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	// +required
	Name string `json:"name"`

	// AccessKeyIDKey is the data key holding the access key ID.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	// +kubebuilder:default="access-key-id"
	// +optional
	AccessKeyIDKey string `json:"accessKeyIdKey,omitempty"`

	// SecretAccessKeyKey is the data key holding the secret access key.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	// +kubebuilder:default="secret-access-key"
	// +optional
	SecretAccessKeyKey string `json:"secretAccessKeyKey,omitempty"`
}

// ReplicationBucket maps a source bucket to a destination bucket.
type ReplicationBucket struct {
	// Source is the bucket name (global alias) on the source cluster.
	// +kubebuilder:validation:MinLength=3
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`
	// +required
	Source string `json:"source"`

	// Destination is the bucket name (global alias) on the destination
	// cluster. It is the list key, so destinations are unique.
	// +kubebuilder:validation:MinLength=3
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`
	// +required
	Destination string `json:"destination"`
}

// ReplicationMirrorConfig configures mode Mirror.
type ReplicationMirrorConfig struct {
	// MaxDeletes caps the number of destination objects one run may delete
	// per bucket. Once reached the run stops and fails with reason
	// MaxDeletesExceeded; deletions done before that point are kept.
	// +kubebuilder:validation:Minimum=1
	// +required
	MaxDeletes int64 `json:"maxDeletes"`
}

// ReplicationTransferConfig tunes the copy engine.
type ReplicationTransferConfig struct {
	// Concurrency is the number of objects transferred in parallel per bucket.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=64
	// +kubebuilder:default=4
	// +optional
	Concurrency int32 `json:"concurrency,omitempty"`

	// Checkers is the number of objects compared in parallel per bucket.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=128
	// +kubebuilder:default=8
	// +optional
	Checkers int32 `json:"checkers,omitempty"`

	// BandwidthLimit caps the transfer rate of each per-bucket Job in bytes
	// per second, with an optional K, M, G suffix (e.g. "50M"). Empty means
	// unlimited.
	// +kubebuilder:validation:MaxLength=32
	// +kubebuilder:validation:Pattern=`^[0-9]+(\.[0-9]+)?[KMGkmg]?$`
	// +optional
	BandwidthLimit string `json:"bandwidthLimit,omitempty"`

	// MaxConcurrentBuckets is the number of buckets replicated in parallel.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=50
	// +kubebuilder:default=1
	// +optional
	MaxConcurrentBuckets int32 `json:"maxConcurrentBuckets,omitempty"`
}

// ReplicationRetryConfig bounds retries and duration of each Job.
type ReplicationRetryConfig struct {
	// BackoffLimit is the number of Pod retries of a per-bucket Job. Each
	// retry restarts the bucket's comparison; already copied objects are
	// skipped.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=10
	// +kubebuilder:default=2
	// +optional
	BackoffLimit *int32 `json:"backoffLimit,omitempty"`

	// ActiveDeadlineSeconds bounds the duration of a per-bucket Job.
	// +kubebuilder:validation:Minimum=60
	// +kubebuilder:default=21600
	// +optional
	ActiveDeadlineSeconds *int64 `json:"activeDeadlineSeconds,omitempty"`
}

// ReplicationPodTemplate customizes replication Pods.
type ReplicationPodTemplate struct {
	// Labels added to the Pods.
	// +kubebuilder:validation:MaxProperties=64
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations added to the Pods.
	// +kubebuilder:validation:MaxProperties=64
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// NodeSelector for the Pods.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations for the Pods.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity for the Pods.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// PriorityClassName for the Pods.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`
}

// ReplicationPhase summarizes the state of a GarageReplication.
// +kubebuilder:validation:Enum=Pending;Idle;Syncing;Suspended;Failed
type ReplicationPhase string

const (
	// ReplicationPhasePending: the configuration is not usable yet.
	ReplicationPhasePending ReplicationPhase = "Pending"
	// ReplicationPhaseIdle: no run in progress and the last run succeeded.
	ReplicationPhaseIdle ReplicationPhase = "Idle"
	// ReplicationPhaseSyncing: a run is in progress.
	ReplicationPhaseSyncing ReplicationPhase = "Syncing"
	// ReplicationPhaseSuspended: spec.suspend is set.
	ReplicationPhaseSuspended ReplicationPhase = "Suspended"
	// ReplicationPhaseFailed: the last run failed.
	ReplicationPhaseFailed ReplicationPhase = "Failed"
)

// ReplicationRunReason is why a run started.
// +kubebuilder:validation:Enum=Initial;Scheduled;Triggered
type ReplicationRunReason string

const (
	// ReplicationRunInitial is the run started when a Copy replication is created.
	ReplicationRunInitial ReplicationRunReason = "Initial"
	// ReplicationRunScheduled is a run started by spec.schedule.
	ReplicationRunScheduled ReplicationRunReason = "Scheduled"
	// ReplicationRunTriggered is a run started by the trigger-sync annotation.
	ReplicationRunTriggered ReplicationRunReason = "Triggered"
)

// ReplicationResult is the outcome of a run or of one bucket's Job.
// +kubebuilder:validation:Enum=Succeeded;Failed;Cancelled
type ReplicationResult string

const (
	// ReplicationResultSucceeded: the copy (and verification) succeeded.
	ReplicationResultSucceeded ReplicationResult = "Succeeded"
	// ReplicationResultFailed: the copy or verification failed.
	ReplicationResultFailed ReplicationResult = "Failed"
	// ReplicationResultCancelled: the Job was deleted or cancelled before it finished.
	ReplicationResultCancelled ReplicationResult = "Cancelled"
)

// ReplicationVerificationResult is the outcome of verification.
// +kubebuilder:validation:Enum=Passed;Failed
type ReplicationVerificationResult string

const (
	// ReplicationVerificationPassed: no difference found.
	ReplicationVerificationPassed ReplicationVerificationResult = "Passed"
	// ReplicationVerificationFailed: differences found.
	ReplicationVerificationFailed ReplicationVerificationResult = "Failed"
)

// ReplicationHold is why a bucket is held. Only the trigger-sync annotation
// releases a hold; editing the spec does not.
// +kubebuilder:validation:Enum=SourceEmpty;MaxDeletesExceeded;AwaitingTrigger
type ReplicationHold string

const (
	// ReplicationHoldSourceEmpty: the source bucket listed empty while the
	// destination was not, so Mirror refused to empty the destination.
	ReplicationHoldSourceEmpty ReplicationHold = "SourceEmpty"
	// ReplicationHoldMaxDeletesExceeded: a Mirror run reached mirror.maxDeletes.
	ReplicationHoldMaxDeletesExceeded ReplicationHold = "MaxDeletesExceeded"
	// ReplicationHoldAwaitingTrigger: a Mirror bucket that never ran waits for
	// a first trigger-sync, so deletions never start without a person asking.
	ReplicationHoldAwaitingTrigger ReplicationHold = "AwaitingTrigger"
)

// ReplicationFailureReason is a fixed reason for a failed Job. Engine output
// (which can contain object keys) stays in the Pod logs.
// +kubebuilder:validation:Enum=AuthFailed;BucketNotFound;EndpointUnreachable;SourceEmpty;MaxDeletesExceeded;VerificationFailed;DeadlineExceeded;TransferErrors;Unknown
type ReplicationFailureReason string

const (
	ReplicationFailureAuthFailed          ReplicationFailureReason = "AuthFailed"
	ReplicationFailureBucketNotFound      ReplicationFailureReason = "BucketNotFound"
	ReplicationFailureEndpointUnreachable ReplicationFailureReason = "EndpointUnreachable"
	ReplicationFailureSourceEmpty         ReplicationFailureReason = "SourceEmpty"
	ReplicationFailureMaxDeletesExceeded  ReplicationFailureReason = "MaxDeletesExceeded"
	ReplicationFailureVerificationFailed  ReplicationFailureReason = "VerificationFailed"
	ReplicationFailureDeadlineExceeded    ReplicationFailureReason = "DeadlineExceeded"
	ReplicationFailureTransferErrors      ReplicationFailureReason = "TransferErrors"
	ReplicationFailureUnknown             ReplicationFailureReason = "Unknown"
)

// GarageReplicationStatus defines the observed state of GarageReplication.
type GarageReplicationStatus struct {
	// Phase summarizes the state.
	// +optional
	Phase ReplicationPhase `json:"phase,omitempty"`

	// ObservedGeneration is the last observed generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// CurrentRun describes the run in progress.
	// +optional
	CurrentRun *ReplicationRun `json:"currentRun,omitempty"`

	// LastRun describes the most recent finished run.
	// +optional
	LastRun *ReplicationRun `json:"lastRun,omitempty"`

	// LastScheduleTime is the start time of the most recent run.
	// +optional
	LastScheduleTime *metav1.Time `json:"lastScheduleTime,omitempty"`

	// LastSyncTime is when the most recent run finished, whatever its result.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// LastSuccessfulSyncTime is when the most recent run in which every
	// bucket succeeded finished.
	// +optional
	LastSuccessfulSyncTime *metav1.Time `json:"lastSuccessfulSyncTime,omitempty"`

	// NextSyncTime is when the next scheduled run starts. Unset without a
	// schedule or while suspended.
	// +optional
	NextSyncTime *metav1.Time `json:"nextSyncTime,omitempty"`

	// Buckets reports per-bucket results, keyed by destination bucket.
	// +listType=map
	// +listMapKey=destination
	// +optional
	Buckets []ReplicationBucketStatus `json:"buckets,omitempty"`

	// LastOperation records the outcome of the last trigger-sync annotation.
	// +optional
	LastOperation *LastOperationStatus `json:"lastOperation,omitempty"`

	// Conditions: Ready (configuration resolved; reasons include
	// CredentialsNotAllowed and DestinationConflict), Synced (every bucket
	// succeeded in the last run on the current configuration), Suspended.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ReplicationRun describes a run.
type ReplicationRun struct {
	// ID identifies the run; it is part of the Job names.
	// +required
	ID string `json:"id"`

	// Reason is why the run started.
	// +required
	Reason ReplicationRunReason `json:"reason"`

	// StartTime is when the run started.
	// +required
	StartTime metav1.Time `json:"startTime"`

	// Trigger is the trigger-sync annotation value that started the run.
	// +optional
	Trigger string `json:"trigger,omitempty"`

	// SpecHash identifies the configuration the run started with.
	// +optional
	SpecHash string `json:"specHash,omitempty"`

	// Buckets lists the destination buckets taking part in the run.
	// +listType=set
	// +optional
	Buckets []string `json:"buckets,omitempty"`

	// CompletionTime is when the run finished.
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// Result is Succeeded when every bucket of the run succeeded, else Failed.
	// +optional
	Result ReplicationResult `json:"result,omitempty"`
}

// ReplicationBucketStatus reports the last result for one bucket.
type ReplicationBucketStatus struct {
	// Destination bucket; the list key.
	// +required
	Destination string `json:"destination"`

	// Source bucket.
	// +required
	Source string `json:"source"`

	// ActiveJob is the Job currently replicating this bucket.
	// +optional
	ActiveJob string `json:"activeJob,omitempty"`

	// LastJob is the last finished Job recorded for this bucket.
	// +optional
	LastJob string `json:"lastJob,omitempty"`

	// LastRunID is the run of LastJob.
	// +optional
	LastRunID string `json:"lastRunId,omitempty"`

	// LastResult is the outcome of LastJob.
	// +optional
	LastResult ReplicationResult `json:"lastResult,omitempty"`

	// LastCompletionTime is when LastJob finished.
	// +optional
	LastCompletionTime *metav1.Time `json:"lastCompletionTime,omitempty"`

	// LastSuccessfulTime is when the last successful Job for this bucket finished.
	// +optional
	LastSuccessfulTime *metav1.Time `json:"lastSuccessfulTime,omitempty"`

	// LastStatistics are the copy engine's counters for LastJob. Unset when
	// the engine reported none (e.g. the Pod was killed).
	// +optional
	LastStatistics *ReplicationStatistics `json:"lastStatistics,omitempty"`

	// LastVerification is the verification outcome when verification ran.
	// +optional
	LastVerification ReplicationVerificationResult `json:"lastVerification,omitempty"`

	// Hold is set when this bucket must not run again without a person
	// asking. Scheduled runs skip a held bucket. Only the trigger-sync
	// annotation releases it; editing the spec does not.
	// +optional
	Hold ReplicationHold `json:"hold,omitempty"`

	// LastError is a fixed reason for a failed LastJob.
	// +optional
	LastError ReplicationFailureReason `json:"lastError,omitempty"`
}

// ReplicationStatistics are counters reported by the copy engine for one Job.
type ReplicationStatistics struct {
	// Transfers is the number of objects written to the destination.
	Transfers int64 `json:"transfers"`
	// Bytes is the number of bytes written to the destination.
	Bytes int64 `json:"bytes"`
	// Checks is the number of objects compared and found up to date.
	Checks int64 `json:"checks"`
	// Deletes is the number of destination objects deleted (Mirror).
	Deletes int64 `json:"deletes"`
	// Errors is the number of errors.
	Errors int64 `json:"errors"`
	// ElapsedSeconds is the duration of the copy.
	ElapsedSeconds int64 `json:"elapsedSeconds"`
	// Differences is the number of differences found by verification.
	// +optional
	Differences *int64 `json:"differences,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=grepl
// +kubebuilder:printcolumn:name="Mode",type="string",JSONPath=".spec.mode"
// +kubebuilder:printcolumn:name="Schedule",type="string",JSONPath=".spec.schedule"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Last Success",type="date",JSONPath=".status.lastSuccessfulSyncTime"
// +kubebuilder:printcolumn:name="Next Sync",type="string",JSONPath=".status.nextSyncTime",priority=1
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GarageReplication is the Schema for the garagereplications API.
// It replicates objects between two independent Garage clusters.
type GarageReplication struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec GarageReplicationSpec `json:"spec"`

	// +optional
	Status GarageReplicationStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// GarageReplicationList contains a list of GarageReplication
type GarageReplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []GarageReplication `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GarageReplication{}, &GarageReplicationList{})
}
