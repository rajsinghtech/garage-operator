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
	"reflect"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
	"github.com/rajsinghtech/garage-operator/internal/garageconfig"
)

// findNodeByIPs returns the node ID whose RPC address matches any of the given pod IPs.
// Handles both IPv4 and IPv6 address formats in the cluster status.
func findNodeByIPs(nodes []garage.NodeInfo, podIPs []string) (string, bool) {
	ipSet := make(map[string]bool, len(podIPs))
	for _, ip := range podIPs {
		ipSet[ip] = true
	}
	// Prefer is_up nodes over stale/dead ones when multiple nodes share an IP (e.g.
	// after an in-place identity change: old dead node still cached at the same address).
	var deadMatch string
	for _, n := range nodes {
		if n.Address != nil && ipSet[extractIPFromAddress(*n.Address)] {
			if n.IsUp {
				return n.ID, true
			}
			if deadMatch == "" {
				deadMatch = n.ID
			}
		}
	}
	if deadMatch != "" {
		return deadMatch, true
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

const nodeClusterUIDTagPrefix = "cluster-uid:"

const (
	kindGarageCluster         = "GarageCluster"
	kindGarageNode            = "GarageNode"
	kindGarageAdminToken      = "GarageAdminToken"
	kindStatefulSet           = "StatefulSet"
	consistencyModeConsistent = "consistent"
	consistencyModeDangerous  = "dangerous"
	annotationPodSpecHash     = "garage.rajsingh.info/pod-spec-hash"
	annotationConfigHash      = "garage.rajsingh.info/config-hash"
)

var operatorManagedNodeLayoutTagPrefixes = []string{
	"cluster:",
	nodeClusterUIDTagPrefix,
	"tier:",
	"rpc-address:",
	"node-local-pool:",
	"kubernetes-node:",
}

func isOperatorManagedNodeLayoutTag(tag string) bool {
	for _, prefix := range operatorManagedNodeLayoutTagPrefixes {
		if strings.HasPrefix(tag, prefix) {
			return true
		}
	}
	return false
}

// userNodeLayoutTags returns only tags users are allowed to own. Keep this
// filter at every controller-generated spec/layout boundary as defense in
// depth for objects persisted before reserved-prefix admission was introduced.
func userNodeLayoutTags(tags []string) []string {
	userTags := make([]string, 0, len(tags))
	for _, tag := range tags {
		if !isOperatorManagedNodeLayoutTag(tag) {
			userTags = append(userTags, tag)
		}
	}
	return userTags
}

// Layout policy constants
const (
	LayoutPolicyManual = "Manual"
	LayoutPolicyAuto   = "Auto"
)

// effectiveStorageLayoutPolicy returns the layout policy governing the STORAGE
// tier: spec.storage.layoutPolicy when set, otherwise the cluster-level
// spec.layoutPolicy. This lets a cluster hand-manage storage GarageNodes
// (Manual) while the gateway tier follows the cluster policy (e.g. stays Auto).
func effectiveStorageLayoutPolicy(cluster *garagev1beta2.GarageCluster) string {
	return cluster.EffectiveStorageLayoutPolicy()
}

// Common secret keys
const (
	DefaultAdminTokenKey   = "admin-token"
	RPCSecretKey           = "rpc-secret"
	remoteAdminTokenKey    = "token"
	metricsTokenVolumeName = "metrics-token"
	consulAPICatalog       = "catalog"
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
	configVolumeName          = "config"
	dataPath                  = "/data/data"
	metadataPath              = "/data/metadata"
	configMountPath           = "/etc/garage"
	configFileName            = "garage.toml"
	rpcSecretMountPath        = "/secrets/rpc"
	adminSecretMountPath      = "/secrets/admin"
	metricsSecretMountPath    = "/secrets/metrics"
	consulCASecretMountPath   = "/secrets/consul/ca"
	consulClientCertMountPath = "/secrets/consul/client-cert"
	consulClientKeyMountPath  = "/secrets/consul/client-key"
	metadataVolName           = "metadata"
	dataVolName               = "data"
	rpcPortName               = "rpc"
	defaultZoneName           = "default"
	operatorName              = "garage-operator"
	msgWaitingForCluster      = "waiting for cluster to be reachable"
)

// publicEndpoint type string constants
const (
	publicEndpointTypeLoadBalancer = "LoadBalancer"
	publicEndpointTypeNodePort     = "NodePort"
)

const (
	envGarageRPCSecret        = "GARAGE_RPC_SECRET"
	envGarageRPCSecretFile    = "GARAGE_RPC_SECRET_FILE"
	envGarageAdminToken       = "GARAGE_ADMIN_TOKEN"
	envGarageAdminTokenFile   = "GARAGE_ADMIN_TOKEN_FILE"
	envGarageMetricsToken     = "GARAGE_METRICS_TOKEN"
	envGarageMetricsTokenFile = "GARAGE_METRICS_TOKEN_FILE"
)

var operatorReservedGarageEnv = map[string]struct{}{
	envGarageConfigFile:       {},
	envGarageRPCSecret:        {},
	envGarageRPCSecretFile:    {},
	envGarageAdminToken:       {},
	envGarageAdminTokenFile:   {},
	envGarageMetricsToken:     {},
	envGarageMetricsTokenFile: {},
}

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
	defaultBucketNameKey      = "bucket"
	defaultCredentialsFileKey = "credentials"
	defaultCredentialsProfile = "default"
	garageKeyKind             = "GarageKey"
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
}

var validScrubCommands = map[string]bool{
	garagev1beta1.ScrubCommandStart:  true,
	garagev1beta1.ScrubCommandPause:  true,
	garagev1beta1.ScrubCommandResume: true,
	garagev1beta1.ScrubCommandCancel: true,
}

// extractIPFromAddress extracts the IP portion from a host:port or [ipv6]:port string.
// IPv6-mapped IPv4 addresses (::ffff:x.x.x.x) are normalized to plain IPv4 so that
// Garage nodes listening on dual-stack [::]  match their Kubernetes pod IP.
func extractIPFromAddress(addr string) string {
	var ip string
	if strings.HasPrefix(addr, "[") {
		if idx := strings.Index(addr, "]:"); idx != -1 {
			ip = addr[1:idx]
		} else if idx := strings.Index(addr, "]"); idx != -1 {
			ip = addr[1:idx]
		} else {
			ip = addr
		}
	} else if idx := strings.LastIndex(addr, ":"); idx != -1 {
		ip = addr[:idx]
	} else {
		ip = addr
	}
	// Normalize ::ffff:x.x.x.x → x.x.x.x
	if v4, ok := strings.CutPrefix(ip, "::ffff:"); ok {
		return v4
	}
	return ip
}

// nodeHasConfigOverrides returns true when a GarageNode has any per-node garage.toml
// overrides requiring a dedicated per-node ConfigMap. This is the canonical definition
// used for ConfigMap creation, volume selection, and config-hash annotation gating.
func nodeHasConfigOverrides(node *garagev1beta1.GarageNode) bool {
	// Gateway nodes always need a dedicated config so they never inherit the
	// storage tier's rpc_public_addr from the shared <cluster>-config. A gateway
	// advertising the storage LB hostname routes RPC peers to the wrong node ID
	// and breaks the handshake (the v0.5.3 cross-cluster outage). The per-node
	// renderer sets OmitClusterRPCPublicAddr for gateway nodes.
	if node.Spec.Gateway {
		return true
	}
	if node.Spec.Network != nil || node.Spec.PublicEndpoint != nil {
		return true
	}
	if node.Spec.Logging != nil {
		return true
	}
	if node.Spec.Storage != nil {
		s := node.Spec.Storage
		if s.MetadataFsync != nil || s.DataFsync != nil {
			return true
		}
		if s.MetadataSnapshotsDir != "" || s.MetadataAutoSnapshotInterval != "" {
			return true
		}
		if len(s.DataPaths) > 0 {
			return true
		}
	}
	return false
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
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
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
	// FinalizationRetryAnnotation records failures for diagnostics. Finalizers
	// are retained until cleanup succeeds; the count never authorizes a leak.
	FinalizationRetryAnnotation = "garage.rajsingh.info/finalization-retries"
	// finalizeRPCTimeout caps a single admin API call on the finalize hot path.
	// Generous compared to a healthy call, short enough that one wedged peer
	// (e.g. a bucket whose authorized_keys lookup never returns) cannot
	// monopolize the whole reconcile.
	finalizeRPCTimeout = 15 * time.Second
)

// GetGarageClient creates a Garage Admin API client for the given cluster.
// This is a shared helper used by all controllers that need to interact with Garage.
// GetAdminToken prefers the operator's table-backed token after it has reached
// every running process, and otherwise uses the immutable static bootstrap
// credential revision.
func GetAdminToken(ctx context.Context, c client.Client, cluster *garagev1beta2.GarageCluster) (string, error) {
	// An unproven dynamic token is deliberately NOT downgraded to the static
	// credential here. This client dials the load-balanced cluster Service, and
	// GetStaticAdminToken returns the cluster's *current* credential revision —
	// which a Pod that started before the last rotation does not have, because
	// Garage reads its config once at startup. Substituting it sends a bearer the
	// receiving process never accepted and earns a 403 from whichever Pod the
	// Service happens to pick, intermittently.
	//
	// Callers that legitimately need to reach Garage while the dynamic token is
	// unprovable must pin to one Pod instead: directVerifiedOperatorAdminClient
	// once a layout is committed, or staticGarageClientForPod before one exists,
	// which reads the credential from that Pod's own spec and so cannot mismatch.
	token, ready, err := getReadyOperatorAdminToken(ctx, c, cluster)
	if err != nil {
		return "", err
	}
	if ready {
		return token, nil
	}
	return GetStaticAdminToken(ctx, c, cluster)
}

// GetStaticAdminToken returns the startup credential mounted into the current
// workload revision. Direct probes of fresh/unassigned identities must use this
// token because Garage's dynamic token table is local and has not replicated to
// a brand-new metadata database yet.
func GetStaticAdminToken(ctx context.Context, c client.Client, cluster *garagev1beta2.GarageCluster) (string, error) {
	if cluster.Spec.Admin == nil || cluster.Spec.Admin.AdminTokenSecretRef == nil {
		return "", fmt.Errorf("admin token not configured on cluster")
	}
	secret := &corev1.Secret{}
	secretName := currentStaticCredentialsSecretName(cluster)
	key := DefaultAdminTokenKey
	if secretName == "" {
		// Initial convergence and unit-test compatibility before the cluster
		// controller has published the first content-addressed revision.
		ref := cluster.Spec.Admin.AdminTokenSecretRef
		secretName = ref.Name
		key = ref.Key
		if key == "" {
			key = DefaultAdminTokenKey
		}
	}
	if err := c.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, secret); err != nil {
		return "", fmt.Errorf("failed to get static admin token secret %s/%s: %w", cluster.Namespace, secretName, err)
	}
	tokenData, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("admin token key %q not found in secret %s", key, secret.Name)
	}
	canonical, err := canonicalStaticBearer(tokenData)
	if err != nil {
		return "", fmt.Errorf("admin token secret %s key %q is invalid: %w", secret.Name, key, err)
	}
	return string(canonical), nil
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
	// A Garage 503 is a transient quorum/timeout/remote-node failure
	// (src/api/common/common_error.rs), retryable just like a dial failure.
	if garage.IsServiceUnavailable(err) {
		return true
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

// GetRPCSecret reads the operator-pinned local RPC identity used by every
// managed workload. External and inherited sources are copied once into this
// immutable Secret by GarageCluster reconciliation; consumers must never race
// a mutable source Secret independently.
func GetRPCSecret(ctx context.Context, c client.Reader, cluster *garagev1beta2.GarageCluster) ([]byte, error) {
	ns := cluster.Namespace
	name := managedRPCSecretName(cluster)
	key := RPCSecretKey

	secret := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, secret); err != nil {
		return nil, fmt.Errorf("failed to get RPC secret %s/%s: %w", ns, name, err)
	}

	raw, ok := secret.Data[key]
	if !ok {
		return nil, fmt.Errorf("RPC secret %s/%s missing key %q", ns, name, key)
	}

	canonical, _, err := canonicalRPCIdentity(raw)
	if err != nil {
		return nil, fmt.Errorf("RPC secret %s/%s key %q is invalid: %w", ns, name, key, err)
	}
	decoded, err := hex.DecodeString(string(canonical))
	if err != nil {
		return nil, fmt.Errorf("decoding canonical RPC secret %s/%s key %q: %w", ns, name, key, err)
	}
	return decoded, nil
}

// GetGarageClient creates a Garage Admin API client for the given cluster.
// NOTE: HTTP is intentional here — Garage does not natively support TLS for its
// Admin API (see TLSConfig docs). The admin endpoint is cluster-internal
// (svc.<clusterDomain>) and authenticated via a bearer token. For TLS, deploy a
// service mesh (Istio/Linkerd) with mTLS or an in-cluster reverse proxy.
func GetGarageClient(ctx context.Context, c client.Client, cluster *garagev1beta2.GarageCluster, clusterDomain string) (*garage.Client, error) {
	return getGarageClient(ctx, c, cluster, clusterDomain, make(map[types.NamespacedName]struct{}), false)
}

// GetGarageClientForCleanup resolves the same fully validated local
// management-handle chain as GetGarageClient, but permits referenced clusters
// that are already deleting. This is cleanup-only: dependent finalizers must
// still reach the dying root in order to remove their remote resources before
// the root finalizer can finish.
func GetGarageClientForCleanup(ctx context.Context, c client.Client, cluster *garagev1beta2.GarageCluster, clusterDomain string) (*garage.Client, error) {
	return getGarageClient(ctx, c, cluster, clusterDomain, make(map[types.NamespacedName]struct{}), true)
}

// resolveGarageLayoutOwner follows connection-only and edge-gateway
// clusterRef chains to the single local object that canonically represents the
// Garage layout. A locally managed storage cluster is its own owner. For an
// external layout, the terminal direct-endpoint management handle/edge object
// is returned; layoutOwnerKey then collapses equivalent endpoint aliases to the
// same process-wide lock key.
//
// Admin-client resolution, coordination, and durable rollout/drain status must
// follow the same chain. Resolving only one hop lets edge -> handle -> storage
// actors acquire different keys for the same upstream staging area.
func resolveGarageLayoutOwner(
	ctx context.Context,
	reader client.Reader,
	cluster *garagev1beta2.GarageCluster,
) (*garagev1beta2.GarageCluster, error) {
	return resolveGarageLayoutOwnerWithPolicy(ctx, reader, cluster, false)
}

// resolveGarageLayoutOwnerForCleanup preserves the same validated, cycle-safe
// chain traversal while allowing a referenced owner that is already deleting.
// Dependent finalizers need the dying root's durable layout transaction until
// their exact roles and workloads have been retired.
func resolveGarageLayoutOwnerForCleanup(
	ctx context.Context,
	reader client.Reader,
	cluster *garagev1beta2.GarageCluster,
) (*garagev1beta2.GarageCluster, error) {
	return resolveGarageLayoutOwnerWithPolicy(ctx, reader, cluster, true)
}

func resolveGarageLayoutOwnerWithPolicy(
	ctx context.Context,
	reader client.Reader,
	cluster *garagev1beta2.GarageCluster,
	allowDeletingReferences bool,
) (*garagev1beta2.GarageCluster, error) {
	if cluster == nil {
		return nil, fmt.Errorf("garageCluster is nil")
	}
	current := cluster
	visited := make(map[types.NamespacedName]struct{})
	for {
		key := types.NamespacedName{Namespace: current.Namespace, Name: current.Name}
		if _, seen := visited[key]; seen {
			return nil, fmt.Errorf("cyclic GarageCluster connectTo.clusterRef chain at %s", key.String())
		}
		visited[key] = struct{}{}

		if current.HasStorageTier() || current.Spec.ConnectTo == nil ||
			(current.IsManagementHandle() && current.Spec.ConnectTo.AdminAPIEndpoint != "") ||
			current.Spec.ConnectTo.ClusterRef == nil {
			return current, nil
		}
		if reader == nil {
			return nil, fmt.Errorf("kubernetes reader is required to resolve GarageCluster connectTo.clusterRef")
		}
		next, err := getLocalConnectToClusterWithPolicy(ctx, reader, current, allowDeletingReferences)
		if err != nil {
			return nil, fmt.Errorf("resolving Garage layout owner from %s: %w", key.String(), err)
		}
		current = next
	}
}

func getGarageClient(
	ctx context.Context,
	c client.Client,
	cluster *garagev1beta2.GarageCluster,
	clusterDomain string,
	visited map[types.NamespacedName]struct{},
	allowDeletingReferences bool,
) (*garage.Client, error) {
	if cluster == nil {
		return nil, fmt.Errorf("garageCluster is nil")
	}
	key := types.NamespacedName{Namespace: cluster.Namespace, Name: cluster.Name}
	if _, seen := visited[key]; seen {
		return nil, fmt.Errorf("cyclic GarageCluster connectTo.clusterRef chain at %s", key.String())
	}
	visited[key] = struct{}{}

	// Management handle (#269): the operator owns no workload for this CR, so
	// there is no managed Service to dial. Resolve the Admin API from
	// spec.connectTo instead. Every controller (bucket, key, cluster) routes
	// through this function, so they all transparently manage the external
	// cluster's Admin-API state.
	if cluster.IsManagementHandle() {
		return resolveConnectToClientWithVisited(ctx, c, cluster, clusterDomain, visited, allowDeletingReferences)
	}

	adminPort := getAdminPort(cluster)
	adminEndpoint := "http://" + svcFQDN(cluster.Name, cluster.Namespace, adminPort, clusterDomain)

	adminToken, err := GetAdminToken(ctx, c, cluster)
	if err != nil {
		return nil, err
	}

	return garage.NewClient(adminEndpoint, adminToken), nil
}

// resolveConnectToClientWithVisited builds an Admin API client from
// spec.connectTo for a management handle. It does not probe reachability;
// callers that need a health signal do that separately. The visited set makes
// clusterRef traversal cycle-safe.
func resolveConnectToClientWithVisited(
	ctx context.Context,
	c client.Client,
	cluster *garagev1beta2.GarageCluster,
	clusterDomain string,
	visited map[types.NamespacedName]struct{},
	allowDeletingReferences bool,
) (*garage.Client, error) {
	ct := cluster.Spec.ConnectTo
	if ct == nil {
		return nil, fmt.Errorf("management handle has no spec.connectTo")
	}

	if ct.AdminAPIEndpoint != "" {
		if ct.AdminTokenSecretRef == nil {
			return nil, fmt.Errorf("connectTo.adminApiEndpoint requires connectTo.adminTokenSecretRef")
		}
		secret := &corev1.Secret{}
		if err := c.Get(ctx, types.NamespacedName{Name: ct.AdminTokenSecretRef.Name, Namespace: cluster.Namespace}, secret); err != nil {
			return nil, fmt.Errorf("failed to get connectTo admin token secret: %w", err)
		}
		key := ct.AdminTokenSecretRef.Key
		if key == "" {
			key = DefaultAdminTokenKey
		}
		token := string(secret.Data[key])
		if token == "" {
			return nil, fmt.Errorf("connectTo admin token secret %s has empty key %q", ct.AdminTokenSecretRef.Name, key)
		}
		return garage.NewClient(ct.AdminAPIEndpoint, token), nil
	}

	if ct.ClusterRef != nil {
		ref, err := getLocalConnectToClusterWithPolicy(ctx, c, cluster, allowDeletingReferences)
		if err != nil {
			return nil, err
		}
		return getGarageClient(ctx, c, ref, clusterDomain, visited, allowDeletingReferences)
	}

	return nil, fmt.Errorf("management handle connectTo missing adminApiEndpoint or clusterRef")
}

func getLocalConnectToClusterWithPolicy(
	ctx context.Context,
	reader client.Reader,
	cluster *garagev1beta2.GarageCluster,
	allowDeleting bool,
) (*garagev1beta2.GarageCluster, error) {
	if cluster == nil || cluster.Spec.ConnectTo == nil || cluster.Spec.ConnectTo.ClusterRef == nil {
		return nil, fmt.Errorf("GarageCluster connectTo.clusterRef is required")
	}
	ref := cluster.Spec.ConnectTo.ClusterRef
	if ref.KubeConfigSecretRef != nil {
		return nil, fmt.Errorf("spec.connectTo.clusterRef.kubeConfigSecretRef is not supported; the operator can reference GarageClusters only through its configured Kubernetes client")
	}
	if err := garageconfig.ValidateNamespacedObjectReference(ref.Name, ref.Namespace, "spec.connectTo.clusterRef"); err != nil {
		return nil, err
	}
	if ref.Namespace != "" && ref.Namespace != cluster.Namespace {
		return nil, fmt.Errorf("spec.connectTo.clusterRef.namespace must be empty or match metadata.namespace")
	}
	objectKey := types.NamespacedName{Name: ref.Name, Namespace: cluster.Namespace}
	next := &garagev1beta2.GarageCluster{}
	if err := reader.Get(ctx, objectKey, next); err != nil {
		return nil, fmt.Errorf("failed to get connectTo clusterRef %s: %w", objectKey, err)
	}
	if !allowDeleting && !next.DeletionTimestamp.IsZero() {
		return nil, fmt.Errorf("connectTo clusterRef %s is deleting", objectKey)
	}
	return next, nil
}

// UpdateStatusWithRetry updates the status subresource with retry on conflict.
// This handles the race condition where concurrent reconciliations may conflict.
//
// An optional mutate callback can recompute status fields after the object is
// re-fetched on conflict. Without a callback, the helper snapshots and restores
// the caller's complete desired Status field before retrying.
//
// Usage:
//
//	UpdateStatusWithRetry(ctx, c, obj, func() {
//	    obj.Status.Phase = desiredPhase
//	    obj.Status.Message = desiredMessage
//	})
func UpdateStatusWithRetry(ctx context.Context, c client.Client, obj client.Object, mutate ...func()) error {
	originalUID := obj.GetUID()
	var desired client.Object
	if len(mutate) == 0 {
		var ok bool
		desired, ok = obj.DeepCopyObject().(client.Object)
		if !ok {
			return fmt.Errorf("cannot snapshot status for %T", obj)
		}
	}
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
			if originalUID != "" && obj.GetUID() != originalUID {
				return fmt.Errorf(
					"refusing to retry status update across object recreation: UID changed from %q to %q",
					originalUID,
					obj.GetUID(),
				)
			}
			// Re-apply desired status changes on the freshly-fetched object
			if len(mutate) == 0 {
				if err := copyStatusField(obj, desired); err != nil {
					return err
				}
			} else {
				for _, fn := range mutate {
					fn()
				}
			}
		}
	}
	return fmt.Errorf("failed to update status after %d retries due to conflicts", StatusUpdateMaxRetries)
}

func copyStatusField(dst, src client.Object) error {
	dstValue := reflect.ValueOf(dst)
	srcValue := reflect.ValueOf(src)
	if dstValue.Kind() != reflect.Pointer || dstValue.IsNil() ||
		srcValue.Kind() != reflect.Pointer || srcValue.IsNil() {
		return fmt.Errorf("status objects must be non-nil pointers, got %T and %T", dst, src)
	}
	if dstValue.Elem().Kind() != reflect.Struct || srcValue.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("status objects must point to structs, got %T and %T", dst, src)
	}
	dstStatus := dstValue.Elem().FieldByName("Status")
	srcStatus := srcValue.Elem().FieldByName("Status")
	if !dstStatus.IsValid() || !srcStatus.IsValid() || !dstStatus.CanSet() || dstStatus.Type() != srcStatus.Type() {
		return fmt.Errorf("cannot copy status from %T to %T", src, dst)
	}
	dstStatus.Set(srcStatus)
	return nil
}

// adoptGarageClusterSnapshot keeps an in-flight reconcile's object internally
// consistent after a helper re-reads or updates the GarageCluster. Copying only
// ResourceVersion is unsafe: the newer snapshot may also contain a concurrent
// status transaction, and a later Status().Update from the older object would
// then have a current resourceVersion while silently erasing that transaction.
func adoptGarageClusterSnapshot(dst, src *garagev1beta2.GarageCluster) {
	if dst == nil || src == nil {
		return
	}
	*dst = *src.DeepCopy()
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

// tagSetEqual compares two layout-role tag slices for equality as multisets
// (order-insensitive, duplicate-aware). It is the single source of truth for
// tag drift detection shared by the cluster and per-node controllers — the two
// must agree on what "tags changed" means or one would churn the layout the
// other considers stable.
func tagSetEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, tag := range a {
		counts[tag]++
	}
	for _, tag := range b {
		if counts[tag] <= 0 {
			return false
		}
		counts[tag]--
	}
	return true
}

func canonicalGarageNodeID(nodeID string) string {
	return garagev1beta1.CanonicalGarageNodeID(nodeID)
}

// shortID truncates a Garage node ID for log output. It returns the full
// string unchanged when shorter than the truncation length, so it is always
// safe on untrusted input (a bare id[:16] slice panics on short strings).
func shortID(id string) string {
	if len(id) > 16 {
		return id[:16] + "..."
	}
	return id
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

// garageBytesize renders Kubernetes storage quantities as exact integral
// bytes. Kubernetes uses a lowercase "m" suffix for milli-units, while
// Garage's bytesize parser treats suffixes case-insensitively and interprets
// "m" as megabytes. Quantity.Value applies Kubernetes' documented rounding to
// the next whole byte, so decimal, binary, and fractional inputs all preserve
// Kubernetes capacity semantics without crossing that grammar boundary.
func garageBytesize(quantity *resource.Quantity) string {
	if quantity == nil {
		return ""
	}
	return strconv.FormatInt(quantity.Value(), 10)
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
	// ReadinessProbe overrides the gateway tier's readiness probe (gateway only).
	// nil => the bind-only TCP default below.
	ReadinessProbe *corev1.Probe
	Logging        *garagev1beta2.LoggingConfig
	// Env is a list of user-supplied environment variables. Ordinary built-ins
	// remain overridable, but GARAGE_CONFIG_FILE is filtered and asserted last so
	// Garage cannot be redirected away from the operator-audited TOML.
	Env []corev1.EnvVar
	// EnvFrom is a list of user-supplied envFrom sources (Secrets, ConfigMaps)
	// to set on the Garage container.
	EnvFrom []corev1.EnvFromSource
}

func garageEnvFromCanOverrideReserved(source corev1.EnvFromSource) bool {
	if source.Prefix == "" {
		return true
	}
	for name := range operatorReservedGarageEnv {
		if strings.HasPrefix(name, source.Prefix) {
			return true
		}
	}
	return false
}

func safeGarageEnvFrom(sources []corev1.EnvFromSource) []corev1.EnvFromSource {
	if len(sources) == 0 {
		return nil
	}
	safe := make([]corev1.EnvFromSource, 0, len(sources))
	for i := range sources {
		if !garageEnvFromCanOverrideReserved(sources[i]) {
			safe = append(safe, sources[i])
		}
	}
	return safe
}

func validateManagedGarageEnvironment(
	env []corev1.EnvVar,
	envFrom []corev1.EnvFromSource,
	field string,
) error {
	for i := range env {
		if _, reserved := operatorReservedGarageEnv[env[i].Name]; reserved {
			return fmt.Errorf("%s.env[%d].name %q is operator-reserved", field, i, env[i].Name)
		}
	}
	for i := range envFrom {
		if garageEnvFromCanOverrideReserved(envFrom[i]) {
			return fmt.Errorf("%s.envFrom[%d].prefix %q can inject an operator-reserved Garage credential or config variable; migrate the source to a non-conflicting prefix", field, i, envFrom[i].Prefix)
		}
	}
	return nil
}

func validateGarageClusterWorkloadEnvironments(cluster *garagev1beta2.GarageCluster) error {
	if cluster == nil {
		return nil
	}
	if err := validateControllerConsulDiscovery(cluster); err != nil {
		return err
	}
	if cluster.Spec.Storage != nil {
		if err := validateManagedGarageEnvironment(
			cluster.Spec.Storage.Env, cluster.Spec.Storage.EnvFrom, "spec.storage",
		); err != nil {
			return err
		}
		for i := range cluster.Spec.Storage.NodeLocalPools {
			pool := &cluster.Spec.Storage.NodeLocalPools[i]
			if pool.PodTemplate == nil {
				continue
			}
			if err := validateManagedGarageEnvironment(
				pool.PodTemplate.Env, pool.PodTemplate.EnvFrom,
				fmt.Sprintf("spec.storage.nodeLocalPools[%q].podTemplate", pool.Name),
			); err != nil {
				return err
			}
		}
	}
	if cluster.Spec.Gateway != nil {
		if err := validateManagedGarageEnvironment(
			cluster.Spec.Gateway.Env, cluster.Spec.Gateway.EnvFrom, "spec.gateway",
		); err != nil {
			return err
		}
	}
	return nil
}

// validateGarageClusterRuntimeSafety is the controller-side backstop for
// released objects that the transition-aware webhook permits only so users can
// repair metadata, finalizers, or the invalid spec. It must run before normal
// secret, ConfigMap, workload, activation, rollout, or layout publication. A
// schema-compatible object is not necessarily safe to reconcile.
func validateGarageClusterRuntimeSafety(cluster *garagev1beta2.GarageCluster) error {
	if cluster == nil {
		return nil
	}
	if cluster.Spec.Storage != nil && cluster.Spec.ConnectTo != nil {
		return fmt.Errorf("spec.storage and spec.connectTo declare conflicting Garage ownership models; remove one before ordinary reconciliation")
	}
	if storage := cluster.Spec.Storage; storage != nil && storage.Replicas > 0 &&
		(storage.Metadata == nil || storage.Data == nil) {
		return fmt.Errorf("spec.storage.replicas is positive but metadata and data are not both configured; add both volumes or scale the default storage group to zero")
	}
	if err := validateGarageClusterWorkloadEnvironments(cluster); err != nil {
		return fmt.Errorf("unsafe managed Garage environment: %w", err)
	}
	return nil
}

func validateGarageNodeRuntimeSafety(node *garagev1beta1.GarageNode) error {
	if node == nil || node.Spec.External != nil || isNodeLocalPoolBacked(node) {
		return nil
	}
	if err := validateManagedGarageEnvironment(node.Spec.Env, node.Spec.EnvFrom, "spec"); err != nil {
		return fmt.Errorf("unsafe managed GarageNode environment: %w", err)
	}
	return nil
}

const maxManagedTierReplicas int32 = 50
const maxManagedGarageNodeNameLength = 61

func validateManagedHeadlessServiceName(clusterName string) error {
	name := clusterName + "-headless"
	if errs := utilvalidation.IsDNS1035Label(name); len(errs) > 0 {
		return fmt.Errorf("managed headless Service name %q is invalid: %s", name, strings.Join(errs, "; "))
	}
	return nil
}

func validateManagedTierReplicas(replicas int32, field string) error {
	if replicas < 0 {
		return fmt.Errorf("%s must be non-negative", field)
	}
	if replicas > maxManagedTierReplicas {
		return fmt.Errorf("%s must be at most %d so every managed StatefulSet Pod and GarageNode name remains a valid Kubernetes label", field, maxManagedTierReplicas)
	}
	return nil
}

func validateManagedGarageNodeName(node *garagev1beta1.GarageNode) error {
	if node == nil {
		return nil
	}
	nameLimit := 63
	if node.Spec.External == nil && !isNodeLocalPoolBacked(node) {
		nameLimit = maxManagedGarageNodeNameLength
	}
	if len(node.Name) > nameLimit {
		return fmt.Errorf("metadata.name %q is too long for this GarageNode backing: maximum %d characters", node.Name, nameLimit)
	}
	return nil
}

// boundedDNS1123LabelName preserves ordinary short names and appends a digest
// when a composed identity would exceed label limits or contains DNS-subdomain
// dots. The digest covers the full unmodified identity, preventing truncation
// collisions between long cluster/pool/node names.
func boundedDNS1123LabelName(identity string) string {
	return boundedDNS1123LabelNameTo(identity, 63)
}

// boundedGarageNodeName leaves two characters for the single-replica
// StatefulSet's `-0` Pod suffix. Kubernetes writes that full Pod name into a
// label value, whose hard limit is 63 characters.
func boundedGarageNodeName(identity string) string {
	return boundedDNS1123LabelNameTo(identity, maxManagedGarageNodeNameLength)
}

func boundedDNS1123LabelNameTo(identity string, maxLength int) string {
	if len(identity) <= maxLength && len(utilvalidation.IsDNS1123Label(identity)) == 0 {
		return identity
	}
	sum := sha256.Sum256([]byte(identity))
	suffix := "-" + hex.EncodeToString(sum[:8])
	prefix := strings.ReplaceAll(strings.ToLower(identity), ".", "-")
	prefix = strings.Trim(prefix, "-")
	maxPrefix := maxLength - len(suffix)
	if len(prefix) > maxPrefix {
		prefix = strings.TrimRight(prefix[:maxPrefix], "-")
	}
	if prefix == "" {
		prefix = defaultAppName
	}
	return prefix + suffix
}

// validateControllerConsulDiscovery repeats the safety-critical admission
// contract at reconciliation time. Webhooks can be disabled or bypassed by
// persisted objects, but the controller must never publish a configuration
// whose fields have different semantics in upstream Garage.
func validateControllerConsulDiscovery(cluster *garagev1beta2.GarageCluster) error {
	if cluster == nil || cluster.Spec.Discovery == nil || cluster.Spec.Discovery.Consul == nil ||
		cluster.Spec.Discovery.Consul.Enabled == nil || !*cluster.Spec.Discovery.Consul.Enabled {
		return nil
	}
	consul := cluster.Spec.Discovery.Consul
	if strings.TrimSpace(consul.HTTPAddr) == "" {
		return fmt.Errorf("spec.discovery.consul.httpAddr is required when Consul discovery is enabled")
	}
	if strings.TrimSpace(consul.ServiceName) == "" {
		return fmt.Errorf("spec.discovery.consul.serviceName is required when Consul discovery is enabled")
	}
	if consul.CACert != "" {
		return fmt.Errorf("spec.discovery.consul.caCert cannot embed a certificate because Garage interprets ca_cert as a file path; use caCertSecretRef")
	}
	if (consul.ClientCertSecretRef == nil) != (consul.ClientKeySecretRef == nil) {
		return fmt.Errorf("spec.discovery.consul.clientCertSecretRef and clientKeySecretRef must be configured together")
	}
	api := consul.API
	if api == "" {
		api = consulAPICatalog
	}
	if api == "agent" && consul.ClientCertSecretRef != nil {
		return fmt.Errorf("spec.discovery.consul client certificate authentication is supported only with api: catalog; Garage ignores it for api: agent")
	}
	return nil
}

func garageUsesGroupReadableCredentialFiles(cluster *garagev1beta2.GarageCluster) bool {
	if garageConfigUsesSecret(cluster) {
		return true
	}
	if cluster == nil || cluster.Spec.Discovery == nil || cluster.Spec.Discovery.Consul == nil {
		return false
	}
	consul := cluster.Spec.Discovery.Consul
	if consul.Enabled == nil || !*consul.Enabled {
		return false
	}
	return consul.CACertSecretRef != nil || consul.ClientCertSecretRef != nil ||
		consul.ClientKeySecretRef != nil
}

func garageContainerRunsAsNonRoot(podSpec corev1.PodSpec) bool {
	var containerSecurityContext *corev1.SecurityContext
	for i := range podSpec.Containers {
		if podSpec.Containers[i].Name == defaultAppName {
			containerSecurityContext = podSpec.Containers[i].SecurityContext
			break
		}
	}
	var runAsUser *int64
	var runAsNonRoot *bool
	if podSpec.SecurityContext != nil {
		runAsUser = podSpec.SecurityContext.RunAsUser
		runAsNonRoot = podSpec.SecurityContext.RunAsNonRoot
	}
	if containerSecurityContext != nil {
		if containerSecurityContext.RunAsUser != nil {
			runAsUser = containerSecurityContext.RunAsUser
		}
		if containerSecurityContext.RunAsNonRoot != nil {
			runAsNonRoot = containerSecurityContext.RunAsNonRoot
		}
	}
	return runAsUser != nil && *runAsUser != 0 || runAsNonRoot != nil && *runAsNonRoot
}

// validateGarageCredentialFileAccess keeps Consul TLS keys and token-bearing
// garage.toml files private without making a declared non-root Garage process
// unable to read them. Kubernetes projects the files root-owned with mode 0440;
// fsGroup supplies the Garage container's supplementary read group.
func validateGarageCredentialFileAccess(
	cluster *garagev1beta2.GarageCluster,
	podSpec corev1.PodSpec,
	workload string,
) error {
	if !garageUsesGroupReadableCredentialFiles(cluster) || !garageContainerRunsAsNonRoot(podSpec) {
		return nil
	}
	if podSpec.SecurityContext == nil || podSpec.SecurityContext.FSGroup == nil {
		return fmt.Errorf("%s declares a non-root Garage container and mounts a token-bearing Garage config or Consul TLS credential files; set its pod securityContext.fsGroup so root-owned mode 0440 files remain private and readable", workload)
	}
	return nil
}

func defaultRPCSecretName(cluster *garagev1beta2.GarageCluster) string {
	return cluster.Name + "-" + RPCSecretKey
}

func managedRPCSecretName(cluster *garagev1beta2.GarageCluster) string {
	if cluster == nil {
		return ""
	}
	if cluster.Spec.Network.RPCSecretRef != nil {
		return cluster.Name + "-rpc-secret-snapshot"
	}
	if cluster.Spec.ConnectTo != nil &&
		(cluster.Spec.ConnectTo.RPCSecretRef != nil || cluster.Spec.ConnectTo.ClusterRef != nil) {
		return cluster.Name + "-rpc-secret-snapshot"
	}
	return defaultRPCSecretName(cluster)
}

// buildGarageCredentialVolumesAndMounts is the single file-path contract used
// by every managed Garage workload. Keeping these mounts together prevents a
// valid shared garage.toml from naming a credential file that only one workload
// shape actually mounts.
func buildGarageCredentialVolumesAndMounts(
	cluster *garagev1beta2.GarageCluster,
	_ bool,
) ([]corev1.Volume, []corev1.VolumeMount) {
	volumes := []corev1.Volume{{
		Name: RPCSecretKey,
		VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName:  managedRPCSecretName(cluster),
			DefaultMode: ptr.To[int32](0600),
			Items:       []corev1.KeyToPath{{Key: RPCSecretKey, Path: RPCSecretKey}},
		}},
	}}
	mounts := []corev1.VolumeMount{{
		Name: RPCSecretKey, MountPath: rpcSecretMountPath, ReadOnly: true,
	}}
	appendSecret := func(name, mountPath string, ref *corev1.SecretKeySelector, defaultKey, projectedKey string, mode int32) {
		if ref == nil {
			return
		}
		key := defaultKey
		if ref.Key != "" {
			key = ref.Key
		}
		volumes = append(volumes, corev1.Volume{
			Name: name,
			VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
				SecretName:  ref.Name,
				DefaultMode: ptr.To(mode),
				Items:       []corev1.KeyToPath{{Key: key, Path: projectedKey}},
			}},
		})
		mounts = append(mounts, corev1.VolumeMount{Name: name, MountPath: mountPath, ReadOnly: true})
	}
	credentialRef := func(logicalKey, defaultKey string, source *corev1.SecretKeySelector) *corev1.SecretKeySelector {
		if source == nil {
			return nil
		}
		if snapshot := currentStaticCredentialsSecretName(cluster); snapshot != "" {
			return &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: snapshot},
				Key:                  logicalKey,
			}
		}
		copy := source.DeepCopy()
		if copy.Key == "" {
			copy.Key = defaultKey
		}
		return copy
	}
	if cluster.Spec.Admin != nil {
		appendSecret(DefaultAdminTokenKey, adminSecretMountPath,
			credentialRef(DefaultAdminTokenKey, DefaultAdminTokenKey, cluster.Spec.Admin.AdminTokenSecretRef),
			DefaultAdminTokenKey, DefaultAdminTokenKey, 0600)
		appendSecret(metricsTokenVolumeName, metricsSecretMountPath,
			credentialRef(metricsTokenVolumeName, metricsTokenVolumeName, cluster.Spec.Admin.MetricsTokenSecretRef),
			metricsTokenVolumeName, metricsTokenVolumeName, 0600)
	}
	if cluster.Spec.Discovery != nil && cluster.Spec.Discovery.Consul != nil &&
		cluster.Spec.Discovery.Consul.Enabled != nil && *cluster.Spec.Discovery.Consul.Enabled {
		consul := cluster.Spec.Discovery.Consul
		appendSecret(consulCACertVolume, consulCASecretMountPath,
			credentialRef(consulCACertKey, consulCACertKey, consul.CACertSecretRef), consulCACertKey, consulCACertKey, 0440)
		appendSecret(consulClientCertVolume, consulClientCertMountPath,
			credentialRef(consulClientCertKey, consulClientCertKey, consul.ClientCertSecretRef), consulClientCertKey, consulClientCertKey, 0440)
		appendSecret(consulClientKeyVolume, consulClientKeyMountPath,
			credentialRef(consulClientKeyKey, consulClientKeyKey, consul.ClientKeySecretRef), consulClientKeyKey, consulClientKeyKey, 0440)
	}
	return volumes, mounts
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
		Name:      envGarageNodeHost,
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
	// Keep ordinary override behavior, but never render a user-controlled config
	// path even if admission was bypassed. Upstream reads consistency_mode and
	// rpc_timeout only from this TOML; trusting the generated config is part of
	// the storage-drain safety proof.
	for i := range cfg.Env {
		if _, reserved := operatorReservedGarageEnv[cfg.Env[i].Name]; !reserved {
			env = append(env, cfg.Env[i])
		}
	}
	appendSecretEnv := func(envName, volumeName, defaultKey string) {
		for i := range volumes {
			secret := volumes[i].Secret
			if volumes[i].Name != volumeName || secret == nil || secret.SecretName == "" {
				continue
			}
			key := defaultKey
			if len(secret.Items) == 1 && secret.Items[0].Key != "" {
				key = secret.Items[0].Key
			}
			env = append(env, corev1.EnvVar{
				Name: envName,
				ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: secret.SecretName},
					Key:                  key,
				}},
			})
			return
		}
	}
	// SecretKeyRef environment values avoid upstream Garage's strict 0600 file
	// ownership trap for non-root pods. The referenced Secrets are immutable and
	// content-addressed, so this remains a restart-only credential contract.
	appendSecretEnv(envGarageRPCSecret, RPCSecretKey, RPCSecretKey)
	appendSecretEnv(envGarageAdminToken, DefaultAdminTokenKey, DefaultAdminTokenKey)
	appendSecretEnv(envGarageMetricsToken, metricsTokenVolumeName, metricsTokenVolumeName)
	env = append(env, corev1.EnvVar{Name: envGarageConfigFile, Value: garageConfigFileLocation})

	container := corev1.Container{
		Name:            defaultAppName,
		Image:           cfg.Image,
		ImagePullPolicy: cfg.ImagePullPolicy,
		Command:         []string{"/garage", "server"},
		Ports:           containerPorts,
		VolumeMounts:    volumeMounts,
		Env:             env,
		EnvFrom:         safeGarageEnvFrom(cfg.EnvFrom),
		Resources:       cfg.Resources,
	}
	if cfg.ContainerSecurityContext != nil {
		container.SecurityContext = cfg.ContainerSecurityContext
	}

	// Readiness probe on the gateway tier only: a bind-only TCP check on :3900
	// (Garage has bound the S3 listener), unless overridden by
	// spec.gateway.readinessProbe (cfg.ReadinessProbe).
	//
	// Deliberately NOT a serving-aware /health probe by default. /health is a
	// cluster-wide CONSISTENT write-quorum signal: at replication.factor=2,
	// losing a single storage node drops every partition below write-quorum, so
	// /health returns 503 on EVERY node (and during federation bootstrap before
	// remote peers join). Gating readiness on that would mark all gateways
	// NotReady and — behind a publishNotReadyAddresses=false Service like the
	// Tailscale anycast — withdraw the entire anycast, taking down READS too,
	// even though read_quorum=1 means reads still work. That is the opposite of
	// the resilience goal (keep serving reads when a region's storage is lost).
	// When a gateway truly can't reach any storage, all gateways can't (shared
	// cluster), so withdrawing them yields no failover benefit. The /health
	// signal therefore lives in MONITORING (the GarageServingUnavailable alert),
	// not readiness. A cluster that wants a custom serving-aware gate (e.g. an
	// exec probe on read-capability) can set spec.gateway.readinessProbe.
	//
	// Storage pods intentionally get no probe: their headless RPC Service sets
	// PublishNotReadyAddresses=true for federation bootstrap, so readiness is
	// ignored anyway.
	//
	// preStop is intentionally absent: the upstream `dxflrs/garage` image is
	// distroless (no `sh`, no `sleep`), so an exec preStop can't delay
	// SIGTERM. The default terminationGracePeriodSeconds of 30 is acceptable
	// for typical rollouts; in-flight requests on a terminating gateway pod
	// can still see RSTs if endpoint-slice propagation lags SIGTERM, but
	// that's a documented edge case requiring a non-distroless base image
	// to fix properly.
	if cfg.IsGateway {
		if cfg.ReadinessProbe != nil {
			container.ReadinessProbe = cfg.ReadinessProbe
		} else {
			container.ReadinessProbe = &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					TCPSocket: &corev1.TCPSocketAction{
						Port: intstr.FromString(s3PortName),
					},
				},
				InitialDelaySeconds: 2,
				PeriodSeconds:       5,
				TimeoutSeconds:      3,
				FailureThreshold:    6,
			}
		}
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
	if !metav1.IsControlledBy(existing, owner) {
		return fmt.Errorf("refusing to mutate Service %s/%s because it is not controlled by exact %T UID %s", existing.Namespace, existing.Name, owner, owner.GetUID())
	}

	existing.Labels = desired.Labels
	existing.Annotations = desired.Annotations
	existing.OwnerReferences = desired.OwnerReferences
	existing.Spec.Type = desired.Spec.Type
	existing.Spec.Selector = desired.Spec.Selector
	existing.Spec.PublishNotReadyAddresses = desired.Spec.PublishNotReadyAddresses
	existing.Spec.ExternalTrafficPolicy = desired.Spec.ExternalTrafficPolicy
	existing.Spec.LoadBalancerIP = desired.Spec.LoadBalancerIP
	existing.Spec.LoadBalancerSourceRanges = append([]string(nil), desired.Spec.LoadBalancerSourceRanges...)
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
