#!/bin/bash
set -euo pipefail

# IPv6 dual-stack e2e test for garage-operator
# Reproduces issue #119: GarageNode autodiscovery on clusters where the pod's
# primary IP is IPv6 (dual-stack with IPv6 listed first in podSubnet).
#
# Tests:
#   1. GarageNode autodiscovery succeeds with IPv6 primary pod IP
#   2. GarageCluster reaches Running state
#   3. Basic S3 connectivity via IPv6 endpoint
#
# Usage: ./hack/e2e-ipv6.sh [--no-cleanup] [--skip-build]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CLUSTER_NAME="garage-e2e-ipv6"
NAMESPACE="garage-operator-system"
TIMEOUT=180

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0

CLEANUP=true
SKIP_BUILD=false
for arg in "$@"; do
    case $arg in
        --no-cleanup) CLEANUP=false ;;
        --skip-build) SKIP_BUILD=true ;;
        --help|-h)
            echo "Usage: $0 [--no-cleanup] [--skip-build]"
            exit 0
            ;;
    esac
done

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_test()  { echo -e "${BLUE}[TEST]${NC} $1"; }

test_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((TESTS_PASSED++)) || true; }
test_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((TESTS_FAILED++)) || true; }

cleanup() {
    if [ "$CLEANUP" = true ]; then
        log_info "Cleaning up kind cluster '$CLUSTER_NAME'..."
        kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
    else
        log_warn "Skipping cleanup. To delete: kind delete cluster --name $CLUSTER_NAME"
    fi
}
trap cleanup EXIT

wait_for_phase() {
    local resource=$1 name=$2 phase=$3 timeout=$4
    local end=$((SECONDS + timeout))
    while [ $SECONDS -lt $end ]; do
        local got
        got=$(kubectl get "$resource" "$name" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
        [ "$got" = "$phase" ] && return 0
        sleep 3
    done
    log_error "$resource/$name did not reach phase '$phase' within ${timeout}s (got: $(kubectl get "$resource" "$name" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo 'unknown'))"
    return 1
}

# ============================================================================
# Setup
# ============================================================================

main() {
    cd "$ROOT_DIR"

    log_info "=== Step 1: Creating dual-stack Kind cluster (IPv6 primary) ==="
    kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
    kind create cluster \
        --name "$CLUSTER_NAME" \
        --config hack/kind-config-ipv6.yaml \
        --wait 90s
    kubectl cluster-info --context "kind-$CLUSTER_NAME"

    # Verify pods actually get IPv6 primary IPs
    log_info "Waiting for kube-system pods to confirm IPv6 primary IPs..."
    sleep 10
    local sample_ip
    sample_ip=$(kubectl get pods -n kube-system -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || echo "")
    if [[ "$sample_ip" == *:* ]]; then
        log_info "Confirmed: primary pod IP is IPv6 ($sample_ip)"
    else
        log_warn "Primary pod IP appears to be IPv4 ($sample_ip) — dual-stack config may not be in effect"
    fi

    log_info "=== Step 2: Building and loading operator image ==="
    if [ "$SKIP_BUILD" = false ]; then
        docker build -t garage-operator:e2e .
        kind load docker-image garage-operator:e2e --name "$CLUSTER_NAME"
    else
        log_info "Skipping build (--skip-build)"
    fi

    log_info "=== Step 3: Deploying operator via Helm ==="
    make install  # Install CRDs
    helm install garage-operator charts/garage-operator \
        --namespace "$NAMESPACE" \
        --create-namespace \
        -f charts/garage-operator/values-e2e.yaml \
        --wait --timeout 120s

    log_info "=== Step 4: Creating test resources ==="
    kubectl create secret generic garage-admin-token -n "$NAMESPACE" \
        --from-literal=admin-token="e2e-ipv6-token-$(date +%s)" 2>/dev/null || true

    # Single-replica cluster (factor 1) — sufficient to exercise node discovery
    kubectl apply -f - <<'EOF'
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageAdminToken
metadata:
  name: garage-admin
  namespace: garage-operator-system
spec:
  clusterRef:
    name: garage
  secretTemplate:
    name: garage-admin-token
---
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: garage
  namespace: garage-operator-system
spec:
  replicas: 1
  image: dxflrs/garage:v2.2.0
  replication:
    factor: 1
  storage:
    metadata:
      size: 1Gi
    data:
      size: 5Gi
  network:
    rpcBindPort: 3901
  admin:
    enabled: true
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
  s3api:
    region: garage
EOF

    # ========================================================================
    # Tests
    # ========================================================================

    log_info "=== Running IPv6 E2E Tests ==="
    echo ""

    # Test 1: GarageCluster reaches Running
    log_test "GarageCluster reaches Running phase..."
    if wait_for_phase "garagecluster" "garage" "Running" "$TIMEOUT"; then
        test_pass "GarageCluster is Running"
    else
        test_fail "GarageCluster did not reach Running"
        kubectl describe garagecluster garage -n "$NAMESPACE" || true
        kubectl logs -n "$NAMESPACE" -l control-plane=controller-manager --tail=50 || true
    fi

    # Test 2: GarageNode has a discovered NodeID (exercises the discovery path)
    log_test "GarageNode autodiscovery with IPv6 primary pod IP..."
    local node_id=""
    local end=$((SECONDS + TIMEOUT))
    while [ $SECONDS -lt $end ]; do
        node_id=$(kubectl get garagenode -n "$NAMESPACE" -o jsonpath='{.items[0].status.nodeId}' 2>/dev/null || echo "")
        [ -n "$node_id" ] && break
        sleep 3
    done
    if [ -n "$node_id" ]; then
        test_pass "GarageNode NodeID discovered: ${node_id:0:16}..."
    else
        test_fail "GarageNode NodeID was not discovered (discovery path failed)"
        kubectl get garagenode -n "$NAMESPACE" -o yaml || true
        kubectl logs -n "$NAMESPACE" -l control-plane=controller-manager --tail=100 | grep -i "node\|discover\|ipv6\|podIP" || true
    fi

    # Test 3: Confirm the pod's primary IP is actually IPv6
    log_test "Garage pod has IPv6 primary pod IP..."
    local pod_ip=""
    pod_ip=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/instance=garage" \
        -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || echo "")
    if [[ "$pod_ip" == *:* ]]; then
        test_pass "Garage pod primary IP is IPv6: $pod_ip"
    else
        test_fail "Garage pod primary IP is not IPv6: $pod_ip (test may not be exercising the fix)"
    fi

    # Test 4: Basic S3 connectivity
    log_test "S3 endpoint reachable..."
    # Port-forward from the S3 service and do a health check
    kubectl port-forward -n "$NAMESPACE" svc/garage-s3 13900:3900 &
    local pf_pid=$!
    sleep 3
    local s3_ok=false
    if curl -sf --max-time 5 http://localhost:13900/ -o /dev/null 2>/dev/null || \
       curl -sf --max-time 5 http://localhost:13900/ 2>&1 | grep -q "InvalidRequest\|AccessDenied\|NoSuchBucket\|ListBuckets\|<?xml"; then
        s3_ok=true
    fi
    kill "$pf_pid" 2>/dev/null || true
    if [ "$s3_ok" = true ]; then
        test_pass "S3 endpoint is reachable"
    else
        test_fail "S3 endpoint not reachable"
    fi

    # ========================================================================
    # Summary
    # ========================================================================
    echo ""
    log_info "========================================"
    log_info "           TEST SUMMARY"
    log_info "========================================"
    echo -e "  ${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "  ${RED}Failed: $TESTS_FAILED${NC}"
    echo ""

    if [ "$TESTS_FAILED" -gt 0 ]; then
        log_error "Some tests failed"
        exit 1
    fi
    log_info "All tests passed"
}

main "$@"
