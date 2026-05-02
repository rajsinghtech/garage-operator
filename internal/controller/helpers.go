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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

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
