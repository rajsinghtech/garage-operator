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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// findNodeByIPs returns the node ID whose RPC address matches any of the given pod IPs.
// Handles both IPv4 and IPv6 address formats in the cluster status.
func findNodeByIPs(nodes []garage.NodeInfo, podIPs []string) (string, bool) {
	ipSet := make(map[string]bool, len(podIPs))
	for _, ip := range podIPs {
		ipSet[ip] = true
	}
	for _, n := range nodes {
		if n.Address != nil && ipSet[extractIPFromAddress(*n.Address)] {
			return n.ID, true
		}
	}
	return "", false
}

// findSelfNode finds the local node in a cluster status response obtained directly from
// the pod's own admin API. Garage sets PeerConnState::Ourself for the local node, which
// serialises as isUp=true with lastSeenSecsAgo absent (nil) — a combination that is
// unique to the self-entry and holds regardless of whether rpc_public_addr is configured.
func findSelfNode(nodes []garage.NodeInfo) (string, bool) {
	for _, n := range nodes {
		if n.IsUp && n.LastSeenSecsAgo == nil {
			return n.ID, true
		}
	}
	return "", false
}

func adminEndpoint(ip string, port int32) string {
	return "http://" + net.JoinHostPort(ip, strconv.Itoa(int(port)))
}

func rpcAddr(ip string, port int32) string {
	return net.JoinHostPort(ip, strconv.Itoa(int(port)))
}

// Common status phases
const (
	PhaseReady    = "Ready"
	PhasePending  = "Pending"
	PhaseRunning  = "Running"
	PhaseFailed   = "Failed"
	PhaseDeleting = "Deleting"
	PhaseExpired  = "Expired"
)

// Layout policy constants
const (
	LayoutPolicyManual = "Manual"
	LayoutPolicyAuto   = "Auto"
)

// Common secret keys
const (
	DefaultAdminTokenKey   = "admin-token"
	RPCSecretKey           = "rpc-secret"
	remoteAdminTokenKey    = "token"
	metricsTokenVolumeName = "metrics-token"
)

// annotationTrue is the canonical value for boolean-style annotations.
const annotationTrue = "true"

// Kubernetes well-known label keys
const (
	labelAppName      = "app.kubernetes.io/name"
	labelAppInstance  = "app.kubernetes.io/instance"
	labelAppComponent = "app.kubernetes.io/component"
	labelAppManagedBy = "app.kubernetes.io/managed-by"
)

// Volume and mount name constants
const (
	configVolumeName     = "config"
	dataPath             = "/data/data"
	adminTokenVolume     = "admin-token"
	metadataVolName      = "metadata"
	dataVolName          = "data"
	rpcPortName          = "rpc"
	defaultZoneName      = "default"
	operatorName         = "garage-operator"
	msgWaitingForCluster = "waiting for cluster to be reachable"
)

// publicEndpoint type string constants
const (
	publicEndpointTypeLoadBalancer = "LoadBalancer"
	publicEndpointTypeNodePort     = "NodePort"
)

// Consul TLS volume name constants
const (
	consulCACertVolume     = "consul-ca-cert"
	consulClientCertVolume = "consul-client-cert"
	consulClientKeyVolume  = "consul-client-key"
	consulCACertKey        = "ca.crt"
	consulClientCertKey    = "tls.crt"
	consulClientKeyKey     = "tls.key"
)

// Secret key name constants for S3 credentials
const (
	defaultAccessKeyIDKey     = "access-key-id"
	defaultSecretAccessKeyKey = "secret-access-key"
	defaultEndpointKey        = "endpoint"
	defaultHostKey            = "host"
	defaultSchemeKey          = "scheme"
	defaultRegionKey          = "region"
)

var validRepairTypes = map[string]bool{
	garagev1beta1.RepairTypeTables:           true,
	garagev1beta1.RepairTypeBlocks:           true,
	garagev1beta1.RepairTypeVersions:         true,
	garagev1beta1.RepairTypeMultipartUploads: true,
	garagev1beta1.RepairTypeBlockRefs:        true,
	garagev1beta1.RepairTypeBlockRc:          true,
	garagev1beta1.RepairTypeRebalance:        true,
	garagev1beta1.RepairTypeAliases:          true,
	garagev1beta1.RepairTypeClearResyncQueue: true,
}

var validScrubCommands = map[string]bool{
	garagev1beta1.ScrubCommandStart:  true,
	garagev1beta1.ScrubCommandPause:  true,
	garagev1beta1.ScrubCommandResume: true,
	garagev1beta1.ScrubCommandCancel: true,
}

// extractIPFromAddress extracts the IP portion from a host:port or [ipv6]:port string.
func extractIPFromAddress(addr string) string {
	if strings.HasPrefix(addr, "[") {
		if idx := strings.Index(addr, "]:"); idx != -1 {
			return addr[1:idx]
		}
		if idx := strings.Index(addr, "]"); idx != -1 {
			return addr[1:idx]
		}
		return addr
	}
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// nodeHasConfigOverrides returns true when a GarageNode has any per-node garage.toml
// overrides requiring a dedicated per-node ConfigMap. This is the canonical definition
// used for ConfigMap creation, volume selection, and config-hash annotation gating.
func nodeHasConfigOverrides(node *garagev1beta1.GarageNode) bool {
	if node.Spec.Network != nil || node.Spec.PublicEndpoint != nil {
		return true
	}
	return node.Spec.Storage != nil &&
		(node.Spec.Storage.MetadataFsync != nil || node.Spec.Storage.DataFsync != nil)
}

// isLikelyInternalAddr returns true when addr looks like a pod or service IP
// rather than an externally-routable address. Hostnames are assumed external.
// Used to detect when Garage is advertising a pod IP that is unreachable from
// an external cluster (i.e. rpc_public_addr was not set in the config).
func isLikelyInternalAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // hostname — assume external
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// Default Garage ports
const (
	DefaultS3Port    = int32(3900)
	DefaultRPCPort   = int32(3901)
	DefaultWebPort   = int32(3902)
	DefaultAdminPort = int32(3903)
	DefaultK2VPort   = int32(3904)
)

// Reconciliation timing constants
const (
	// RequeueAfterError is the delay before requeuing after an error
	RequeueAfterError = 30 * time.Second
	// RequeueAfterUnhealthy is a fast delay for reconnecting unhealthy clusters
	RequeueAfterUnhealthy = 10 * time.Second
	// RequeueAfterShort is a short delay for periodic reconciliation
	RequeueAfterShort = 1 * time.Minute
	// RequeueAfterLong is a longer delay for stable resources
	RequeueAfterLong = 5 * time.Minute
	// RequeueAfterDrift is the interval for periodic credential drift checks on idle healthy resources
	RequeueAfterDrift = 5 * time.Minute
	// StatusUpdateMaxRetries is the maximum number of retries for status updates
	StatusUpdateMaxRetries = 3
)

// Finalization constants
const (
	// FinalizationMaxRetries is tracked via annotation on the resource
	FinalizationRetryAnnotation = "garage.rajsingh.info/finalization-retries"
	// FinalizationMaxRetries before giving up and removing finalizer
	FinalizationMaxRetries = 5
)

// GetGarageClient creates a Garage Admin API client for the given cluster.
// This is a shared helper used by all controllers that need to interact with Garage.
// GetAdminToken retrieves the admin token from the cluster's secret.
func GetAdminToken(ctx context.Context, c client.Client, cluster *garagev1beta1.GarageCluster) (string, error) {
	if cluster.Spec.Admin == nil || cluster.Spec.Admin.AdminTokenSecretRef == nil {
		return "", fmt.Errorf("admin token not configured on cluster")
	}

	secret := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{
		Name:      cluster.Spec.Admin.AdminTokenSecretRef.Name,
		Namespace: cluster.Namespace,
	}, secret); err != nil {
		return "", fmt.Errorf("failed to get admin token secret: %w", err)
	}

	if secret.Data == nil {
		return "", fmt.Errorf("admin token secret %s has no data", secret.Name)
	}

	tokenKey := DefaultAdminTokenKey
	if cluster.Spec.Admin.AdminTokenSecretRef.Key != "" {
		tokenKey = cluster.Spec.Admin.AdminTokenSecretRef.Key
	}

	tokenData, ok := secret.Data[tokenKey]
	if !ok {
		return "", fmt.Errorf("admin token key %q not found in secret %s", tokenKey, secret.Name)
	}
	adminToken := string(tokenData)
	if adminToken == "" {
		return "", fmt.Errorf("admin token is empty in secret %s", secret.Name)
	}

	return adminToken, nil
}

// svcFQDN returns the FQDN for a Kubernetes service with port, using the given cluster domain.
// Example: svcFQDN("garage", "default", 3903, "cluster.local") → "garage.default.svc.cluster.local:3903"
func svcFQDN(name, namespace string, port int32, clusterDomain string) string {
	return fmt.Sprintf("%s.%s.svc.%s:%d", name, namespace, clusterDomain, port)
}

// isTransientConnectivityError returns true for errors that indicate the cluster
// service is temporarily unreachable (DNS not yet propagated, pod not yet ready,
// etc.) and should be retried without surfacing as a permanent error condition.
func isTransientConnectivityError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, substr := range []string{
		"no such host",
		"connection refused",
		"dial tcp",
		"i/o timeout",
	} {
		if strings.Contains(msg, substr) {
			return true
		}
	}
	return false
}

// deriveKeyMaterial derives a deterministic Garage access key ID and secret
// from the shared RPC secret and a per-key identity string. Using the federation's
// RPC secret as the HMAC key guarantees all operators in the same ring produce
// identical material for identical inputs, eliminating creation races.
//
// Output formats satisfy Garage's ImportKey constraints:
//
//	access_key_id: "GK" + 24 hex chars (26 total, alphanumeric only) ✓
//	secret_access_key: 64 hex chars (graphic ASCII, len >= 16) ✓
func deriveKeyMaterial(rpcSecret []byte, namespace, keyName string) (accessKeyID, secretKey string) {
	identity := namespace + "/" + keyName

	akMAC := hmac.New(sha256.New, rpcSecret)
	akMAC.Write([]byte("ak:" + identity))
	accessKeyID = "GK" + hex.EncodeToString(akMAC.Sum(nil)[:12])

	skMAC := hmac.New(sha256.New, rpcSecret)
	skMAC.Write([]byte("sk:" + identity))
	secretKey = hex.EncodeToString(skMAC.Sum(nil))

	return
}

// GetRPCSecret reads the raw RPC secret bytes for the cluster.
// For federated clusters, it reads from spec.network.rpcSecretRef.
// For non-federated clusters, it falls back to the auto-generated <cluster>-rpc-secret Secret.
func GetRPCSecret(ctx context.Context, c client.Client, cluster *garagev1beta1.GarageCluster) ([]byte, error) {
	ns := cluster.Namespace
	name := cluster.Name + "-" + RPCSecretKey
	key := RPCSecretKey

	if cluster.Spec.Network.RPCSecretRef != nil {
		name = cluster.Spec.Network.RPCSecretRef.Name
		if cluster.Spec.Network.RPCSecretRef.Key != "" {
			key = cluster.Spec.Network.RPCSecretRef.Key
		}
	}

	secret := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, secret); err != nil {
		return nil, fmt.Errorf("failed to get RPC secret %s/%s: %w", ns, name, err)
	}

	raw, ok := secret.Data[key]
	if !ok {
		return nil, fmt.Errorf("RPC secret %s/%s missing key %q", ns, name, key)
	}

	// The secret stores a hex-encoded 32-byte value; decode to raw bytes for use as HMAC key
	decoded := make([]byte, hex.DecodedLen(len(raw)))
	n, err := hex.Decode(decoded, raw)
	if err != nil {
		return nil, fmt.Errorf("RPC secret %s/%s key %q is not valid hex: %w", ns, name, key, err)
	}
	return decoded[:n], nil
}

// GetGarageClient creates a Garage Admin API client for the given cluster.
// NOTE: HTTP is intentional here — Garage does not natively support TLS for its
// Admin API (see TLSConfig docs). The admin endpoint is cluster-internal
// (svc.<clusterDomain>) and authenticated via a bearer token. For TLS, deploy a
// service mesh (Istio/Linkerd) with mTLS or an in-cluster reverse proxy.
func GetGarageClient(ctx context.Context, c client.Client, cluster *garagev1beta1.GarageCluster, clusterDomain string) (*garage.Client, error) {
	adminPort := DefaultAdminPort
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.BindPort != 0 {
		adminPort = cluster.Spec.Admin.BindPort
	}
	adminEndpoint := "http://" + svcFQDN(cluster.Name, cluster.Namespace, adminPort, clusterDomain)

	adminToken, err := GetAdminToken(ctx, c, cluster)
	if err != nil {
		return nil, err
	}

	return garage.NewClient(adminEndpoint, adminToken), nil
}

// s3EndpointURL returns the in-cluster S3 endpoint URL for a Garage cluster.
// the same Service that fronts the admin port also fronts the S3 port.
func s3EndpointURL(cluster *garagev1beta1.GarageCluster, clusterDomain string) string {
	port := DefaultS3Port
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.BindPort != 0 {
		port = cluster.Spec.S3API.BindPort
	}
	return "http://" + svcFQDN(cluster.Name, cluster.Namespace, port, clusterDomain)
}

// s3Region returns the region configured on the cluster, or the Garage
// default ("garage") when unset.
func s3Region(cluster *garagev1beta1.GarageCluster) string {
	if cluster.Spec.S3API != nil && cluster.Spec.S3API.Region != "" {
		return cluster.Spec.S3API.Region
	}
	return defaultS3Region
}

// UpdateStatusWithRetry updates the status subresource with retry on conflict.
// This handles the race condition where concurrent reconciliations may conflict.
//
// An optional mutate callback can be provided to re-apply status fields after
// the object is re-fetched on conflict. Without a mutate callback, the re-fetched
// object's status would overwrite any pending status changes — effectively losing
// the update the caller intended to persist.
//
// Usage:
//
//	UpdateStatusWithRetry(ctx, c, obj, func() {
//	    obj.Status.Phase = desiredPhase
//	    obj.Status.Message = desiredMessage
//	})
func UpdateStatusWithRetry(ctx context.Context, c client.Client, obj client.Object, mutate ...func()) error {
	for i := 0; i < StatusUpdateMaxRetries; i++ {
		err := c.Status().Update(ctx, obj)
		if err == nil {
			return nil
		}
		if !errors.IsConflict(err) {
			return err
		}
		// On conflict, re-fetch the object and retry
		if i < StatusUpdateMaxRetries-1 {
			if err := c.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
				return fmt.Errorf("failed to re-fetch object after conflict: %w", err)
			}
			// Re-apply desired status changes on the freshly-fetched object
			for _, fn := range mutate {
				fn()
			}
		}
	}
	return fmt.Errorf("failed to update status after %d retries due to conflicts", StatusUpdateMaxRetries)
}

// GetFinalizationRetryCount returns the current finalization retry count from annotations
func GetFinalizationRetryCount(obj client.Object) int {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return 0
	}
	countStr, ok := annotations[FinalizationRetryAnnotation]
	if !ok {
		return 0
	}
	count, err := strconv.Atoi(countStr)
	if err != nil {
		return 0
	}
	return count
}

// IncrementFinalizationRetryCount increments the finalization retry count annotation
func IncrementFinalizationRetryCount(obj client.Object) {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	count := GetFinalizationRetryCount(obj)
	annotations[FinalizationRetryAnnotation] = strconv.Itoa(count + 1)
	obj.SetAnnotations(annotations)
}

// ShouldSkipFinalization returns true if finalization has failed too many times
func ShouldSkipFinalization(obj client.Object) bool {
	return GetFinalizationRetryCount(obj) >= FinalizationMaxRetries
}

// splitTrimmed splits s on commas and trims whitespace from each element,
// returning only non-empty results.
func splitTrimmed(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// defaultAccessModes returns [ReadWriteOnce], the default PVC access mode.
func defaultAccessModes() []corev1.PersistentVolumeAccessMode {
	return []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}
}

// buildBasePVC creates a PersistentVolumeClaim with common fields populated.
// accessModes defaults to [ReadWriteOnce] when nil or empty.
// Callers can further customize the returned PVC (Labels, Annotations, Selector, etc.).
func buildBasePVC(name string, size resource.Quantity, storageClassName *string, accessModes []corev1.PersistentVolumeAccessMode) corev1.PersistentVolumeClaim {
	if len(accessModes) == 0 {
		accessModes = defaultAccessModes()
	}
	return corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: accessModes,
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: size,
				},
			},
			StorageClassName: storageClassName,
		},
	}
}

// PodSpecConfig holds resolved pod spec values used by both GarageCluster and
// GarageNode controllers. All fields are already merged/resolved before this
// struct is constructed — no further defaulting happens inside buildGaragePodSpec.
type PodSpecConfig struct {
	Image                     string
	ImagePullPolicy           corev1.PullPolicy
	ImagePullSecrets          []corev1.LocalObjectReference
	Resources                 corev1.ResourceRequirements
	NodeSelector              map[string]string
	Tolerations               []corev1.Toleration
	Affinity                  *corev1.Affinity
	PriorityClassName         string
	ServiceAccountName        string
	SecurityContext           *corev1.PodSecurityContext
	ContainerSecurityContext  *corev1.SecurityContext
	TopologySpreadConstraints []corev1.TopologySpreadConstraint
	IsGateway                 bool
	Logging                   *garagev1beta1.LoggingConfig
}

// buildGaragePodSpec constructs a corev1.PodSpec for a Garage container.
// The caller is responsible for computing pod-spec-hash from the returned spec.
func buildGaragePodSpec(
	cfg PodSpecConfig,
	volumes []corev1.Volume,
	volumeMounts []corev1.VolumeMount,
	containerPorts []corev1.ContainerPort,
) corev1.PodSpec {
	env := []corev1.EnvVar{{
		Name:      "GARAGE_NODE_HOST",
		ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}},
	}}
	if l := cfg.Logging; l != nil {
		if l.Level != "" {
			env = append(env, corev1.EnvVar{Name: "RUST_LOG", Value: l.Level})
		}
		if l.Syslog {
			env = append(env, corev1.EnvVar{Name: "GARAGE_LOG_TO_SYSLOG", Value: "1"})
		}
		if l.Journald {
			env = append(env, corev1.EnvVar{Name: "GARAGE_LOG_TO_JOURNALD", Value: "1"})
		}
	}

	container := corev1.Container{
		Name:            defaultAppName,
		Image:           cfg.Image,
		ImagePullPolicy: cfg.ImagePullPolicy,
		Command:         []string{"/garage", "-c", "/etc/garage/garage.toml", "server"},
		Ports:           containerPorts,
		VolumeMounts:    volumeMounts,
		Env:             env,
		Resources:       cfg.Resources,
	}
	if cfg.ContainerSecurityContext != nil {
		container.SecurityContext = cfg.ContainerSecurityContext
	}

	podSpec := corev1.PodSpec{
		Containers:         []corev1.Container{container},
		Volumes:            volumes,
		ServiceAccountName: cfg.ServiceAccountName,
		NodeSelector:       cfg.NodeSelector,
		Tolerations:        cfg.Tolerations,
		Affinity:           cfg.Affinity,
		ImagePullSecrets:   cfg.ImagePullSecrets,
	}

	if cfg.IsGateway {
		initSC := cfg.ContainerSecurityContext
		if initSC == nil {
			initSC = &corev1.SecurityContext{
				RunAsNonRoot:             ptr.To(true),
				RunAsUser:                ptr.To[int64](65532),
				AllowPrivilegeEscalation: ptr.To(false),
				ReadOnlyRootFilesystem:   ptr.To(true),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			}
		}
		podSpec.InitContainers = []corev1.Container{{
			Name:    "init-marker",
			Image:   "busybox:1.37",
			Command: []string{"touch", dataPath + "/garage-marker"},
			VolumeMounts: []corev1.VolumeMount{
				{Name: dataVolName, MountPath: dataPath},
			},
			SecurityContext: initSC,
		}}
	}

	if cfg.SecurityContext != nil {
		podSpec.SecurityContext = cfg.SecurityContext
	}
	if cfg.PriorityClassName != "" {
		podSpec.PriorityClassName = cfg.PriorityClassName
	}
	if len(cfg.TopologySpreadConstraints) > 0 {
		podSpec.TopologySpreadConstraints = cfg.TopologySpreadConstraints
	}

	return podSpec
}

// mergeLabels merges user labels with operator-managed base labels. Base labels take
// precedence so users cannot overwrite ownership labels.
func mergeLabels(base, user map[string]string) map[string]string {
	if len(user) == 0 {
		return base
	}
	out := make(map[string]string, len(base)+len(user))
	for k, v := range user {
		out[k] = v
	}
	for k, v := range base {
		out[k] = v
	}
	return out
}

// reconcileService creates or updates a Service. On update, only mutable fields are
// written back to avoid overwriting immutable fields (ClusterIP) or Kubernetes-allocated
// values (NodePort when BasePort is not configured).
func reconcileService(ctx context.Context, c client.Client, desired *corev1.Service, owner client.Object, scheme *runtime.Scheme) error {
	if err := controllerutil.SetControllerReference(owner, desired, scheme); err != nil {
		return err
	}

	existing := &corev1.Service{}
	err := c.Get(ctx, types.NamespacedName{Name: desired.Name, Namespace: desired.Namespace}, existing)
	if errors.IsNotFound(err) {
		return c.Create(ctx, desired)
	}
	if err != nil {
		return err
	}

	existing.Labels = desired.Labels
	existing.Annotations = desired.Annotations
	existing.Spec.Type = desired.Spec.Type
	existing.Spec.Selector = desired.Spec.Selector
	existing.Spec.PublishNotReadyAddresses = desired.Spec.PublishNotReadyAddresses
	existing.Spec.ExternalTrafficPolicy = desired.Spec.ExternalTrafficPolicy
	// Merge ports: preserve Kubernetes-allocated NodePort values when the desired
	// port has NodePort == 0 (i.e. caller did not request a specific port).
	existing.Spec.Ports = mergeServicePorts(existing.Spec.Ports, desired.Spec.Ports)
	return c.Update(ctx, existing)
}

// mergeServicePorts merges desired ports into existing, preserving allocated NodePort
// values where the desired port specifies NodePort == 0.
func mergeServicePorts(existing, desired []corev1.ServicePort) []corev1.ServicePort {
	existingByName := make(map[string]corev1.ServicePort, len(existing))
	for _, p := range existing {
		existingByName[p.Name] = p
	}
	merged := make([]corev1.ServicePort, 0, len(desired))
	for _, dp := range desired {
		if dp.NodePort == 0 {
			if ep, ok := existingByName[dp.Name]; ok {
				dp.NodePort = ep.NodePort
			}
		}
		merged = append(merged, dp)
	}
	return merged
}
