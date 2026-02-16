#!/bin/bash
set -euo pipefail

# COSI E2E test script for garage-operator
# Tests the Container Object Storage Interface (COSI) driver
# Usage: ./hack/e2e-cosi.sh [--no-cleanup] [--skip-build]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CLUSTER_NAME="garage-cosi-e2e"
NAMESPACE="garage-operator-system"
COSI_NAMESPACE="default"
TIMEOUT=120
# COSI CRDs require k8s 1.31+ for CEL format validation
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.35.0}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Parse arguments
CLEANUP=true
SKIP_BUILD=false
for arg in "$@"; do
    case $arg in
        --no-cleanup) CLEANUP=false ;;
        --skip-build) SKIP_BUILD=true ;;
        --help|-h)
            echo "Usage: $0 [--no-cleanup] [--skip-build]"
            echo "  --no-cleanup  Don't delete the kind cluster after tests"
            echo "  --skip-build  Skip building the operator image"
            exit 0
            ;;
    esac
done

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_test() { echo -e "${BLUE}[TEST]${NC} $1"; }

test_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++)) || true
}

test_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++)) || true
}

test_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    ((TESTS_SKIPPED++)) || true
}

cleanup() {
    if [ "$CLEANUP" = true ]; then
        log_info "Cleaning up kind cluster..."
        kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
    else
        log_warn "Skipping cleanup. Cluster '$CLUSTER_NAME' still running."
        log_info "To delete: kind delete cluster --name $CLUSTER_NAME"
    fi
}

trap cleanup EXIT

wait_for_condition() {
    local resource=$1
    local condition=$2
    local timeout=$3
    local namespace=${4:-$NAMESPACE}

    if ! kubectl wait "$resource" --for="$condition" --timeout="${timeout}s" -n "$namespace" 2>/dev/null; then
        return 1
    fi
    return 0
}

wait_for_pods_ready() {
    local selector=$1
    local expected_count=$2
    local timeout=$3

    log_info "Waiting for $expected_count pods with selector '$selector' to be ready..."
    local end_time=$((SECONDS + timeout))

    while [ $SECONDS -lt $end_time ]; do
        local ready_pods
        ready_pods=$(kubectl get pods -n "$NAMESPACE" -l "$selector" -o jsonpath='{range .items[*]}{.status.containerStatuses[*].ready}{"\n"}{end}' 2>/dev/null | grep -c "true" || true)
        ready_pods=${ready_pods:-0}

        if [ "$ready_pods" -ge "$expected_count" ]; then
            log_info "All $expected_count pods are ready"
            return 0
        fi
        sleep 2
    done

    log_error "Timeout waiting for pods"
    kubectl get pods -n "$NAMESPACE" -l "$selector" 2>/dev/null || true
    return 1
}

check_resource_phase() {
    local resource_type=$1
    local resource_name=$2
    local expected_phase=$3
    local timeout=$4
    local namespace=${5:-$NAMESPACE}

    local end_time=$((SECONDS + timeout))
    while [ $SECONDS -lt $end_time ]; do
        local phase
        phase=$(kubectl get "$resource_type" "$resource_name" -n "$namespace" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
        if [ "$phase" = "$expected_phase" ]; then
            return 0
        fi
        sleep 2
    done
    return 1
}

wait_for_cosi_ready() {
    local resource_type=$1
    local resource_name=$2
    local timeout=$3
    local namespace=${4:-$COSI_NAMESPACE}

    log_info "Waiting for $resource_type/$resource_name to be ready..."
    local end_time=$((SECONDS + timeout))
    while [ $SECONDS -lt $end_time ]; do
        local ready
        ready=$(kubectl get "$resource_type" "$resource_name" -n "$namespace" -o jsonpath='{.status.readyToUse}' 2>/dev/null || echo "false")
        if [ "$ready" = "true" ]; then
            return 0
        fi
        sleep 2
    done
    return 1
}

collect_debug_info() {
    log_warn "Collecting debug info..."
    echo "--- Operator pods ---"
    kubectl get pods -n "$NAMESPACE" -o wide 2>/dev/null || true
    echo "--- Operator logs ---"
    kubectl logs deployment/garage-operator -n "$NAMESPACE" --tail=50 2>/dev/null || true
    echo "--- COSI resources ---"
    kubectl get bucketclass,bucketaccessclass 2>/dev/null || true
    kubectl get bucketclaim,bucketaccess -n "$COSI_NAMESPACE" 2>/dev/null || true
    echo "--- GarageCluster ---"
    kubectl get garagecluster -n "$NAMESPACE" -o wide 2>/dev/null || true
    echo "--- GarageBuckets ---"
    kubectl get garagebucket -n "$NAMESPACE" -o wide 2>/dev/null || true
    echo "--- GarageKeys ---"
    kubectl get garagekey -n "$NAMESPACE" -o wide 2>/dev/null || true
    echo "--- Events ---"
    kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' --field-selector type!=Normal 2>/dev/null | tail -20 || true
    kubectl get events -n "$COSI_NAMESPACE" --sort-by='.lastTimestamp' --field-selector type!=Normal 2>/dev/null | tail -20 || true
}

# ============================================================================
# Test Functions
# ============================================================================

test_cosi_sidecar_running() {
    log_test "Testing COSI sidecar is running..."

    # The operator pod should have 2 containers: manager + cosi-sidecar
    local container_count
    container_count=$(kubectl get pod -l app.kubernetes.io/name=garage-operator -n "$NAMESPACE" \
        -o jsonpath='{.items[0].spec.containers[*].name}' 2>/dev/null | wc -w | tr -d ' ')

    if [ "$container_count" -ge "2" ]; then
        test_pass "COSI sidecar running (operator pod has $container_count containers)"
        return 0
    fi
    test_fail "COSI sidecar not found (operator pod has $container_count containers)"
    return 1
}

test_garage_cluster_ready() {
    log_test "Testing GarageCluster is ready..."

    if check_resource_phase "garagecluster" "garage" "Running" 120; then
        test_pass "GarageCluster is Running"
        return 0
    fi

    local phase
    phase=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
    test_fail "GarageCluster not ready (phase: $phase)"
    return 1
}

test_bucket_claim_bound() {
    log_test "Testing BucketClaim gets bound..."

    kubectl apply -f "$ROOT_DIR/config/samples/cosi/bucketclass.yaml"
    kubectl apply -f "$ROOT_DIR/config/samples/cosi/bucketclaim.yaml"

    if wait_for_cosi_ready "bucketclaim" "my-bucket" 120 "$COSI_NAMESPACE"; then
        test_pass "BucketClaim 'my-bucket' is ready"
        return 0
    fi

    local status
    status=$(kubectl get bucketclaim my-bucket -n "$COSI_NAMESPACE" -o jsonpath='{.status}' 2>/dev/null || echo "{}")
    test_fail "BucketClaim not ready: $status"
    return 1
}

test_shadow_bucket_created() {
    log_test "Testing shadow GarageBucket was created..."

    local count
    count=$(kubectl get garagebucket -n "$NAMESPACE" -l "garage.rajsingh.info/cosi-managed=true" --no-headers 2>/dev/null | wc -l | tr -d ' ')

    if [ "$count" -ge "1" ]; then
        local bucket_name
        bucket_name=$(kubectl get garagebucket -n "$NAMESPACE" -l "garage.rajsingh.info/cosi-managed=true" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
        test_pass "Shadow GarageBucket created: $bucket_name"
        return 0
    fi
    test_fail "No shadow GarageBucket found with cosi-managed label"
    return 1
}

test_bucket_access_credentials() {
    log_test "Testing BucketAccess creates credentials..."

    kubectl apply -f "$ROOT_DIR/config/samples/cosi/bucketaccessclass.yaml"
    kubectl apply -f "$ROOT_DIR/config/samples/cosi/bucketaccess.yaml"

    if wait_for_cosi_ready "bucketaccess" "my-bucket-access" 120 "$COSI_NAMESPACE"; then
        # Verify the credentials secret was created
        local secret_exists
        secret_exists=$(kubectl get secret my-bucket-creds -n "$COSI_NAMESPACE" -o name 2>/dev/null || echo "")
        if [ -n "$secret_exists" ]; then
            # Verify the secret has expected keys
            local keys
            keys=$(kubectl get secret my-bucket-creds -n "$COSI_NAMESPACE" -o jsonpath='{.data}' 2>/dev/null | python3 -c "import sys,json; print(' '.join(json.load(sys.stdin).keys()))" 2>/dev/null || echo "")
            test_pass "BucketAccess ready, credentials secret created with keys: $keys"
            return 0
        fi
        test_fail "BucketAccess ready but credentials secret not found"
        return 1
    fi

    local status
    status=$(kubectl get bucketaccess my-bucket-access -n "$COSI_NAMESPACE" -o jsonpath='{.status}' 2>/dev/null || echo "{}")
    test_fail "BucketAccess not ready: $status"
    return 1
}

test_shadow_key_created() {
    log_test "Testing shadow GarageKey was created..."

    local count
    count=$(kubectl get garagekey -n "$NAMESPACE" -l "garage.rajsingh.info/cosi-managed=true" --no-headers 2>/dev/null | wc -l | tr -d ' ')

    if [ "$count" -ge "1" ]; then
        local key_name
        key_name=$(kubectl get garagekey -n "$NAMESPACE" -l "garage.rajsingh.info/cosi-managed=true" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
        test_pass "Shadow GarageKey created: $key_name"
        return 0
    fi
    test_fail "No shadow GarageKey found with cosi-managed label"
    return 1
}

test_bucket_access_cleanup() {
    log_test "Testing BucketAccess cleanup..."

    kubectl delete bucketaccess my-bucket-access -n "$COSI_NAMESPACE" --timeout=60s 2>/dev/null || true

    # Wait for credentials secret to be cleaned up
    local end_time=$((SECONDS + 60))
    while [ $SECONDS -lt $end_time ]; do
        if ! kubectl get secret my-bucket-creds -n "$COSI_NAMESPACE" 2>/dev/null; then
            test_pass "BucketAccess cleanup: credentials secret removed"
            return 0
        fi
        sleep 2
    done

    test_fail "BucketAccess cleanup: credentials secret still exists"
    return 1
}

test_bucket_claim_cleanup() {
    log_test "Testing BucketClaim cleanup (deletionPolicy: Delete)..."

    kubectl delete bucketclaim my-bucket -n "$COSI_NAMESPACE" --timeout=60s 2>/dev/null || true

    # Wait for shadow GarageBucket to be cleaned up
    local end_time=$((SECONDS + 60))
    while [ $SECONDS -lt $end_time ]; do
        local count
        count=$(kubectl get garagebucket -n "$NAMESPACE" -l "garage.rajsingh.info/cosi-managed=true" --no-headers 2>/dev/null | wc -l | tr -d ' ')
        if [ "$count" -eq "0" ]; then
            test_pass "BucketClaim cleanup: shadow GarageBucket removed"
            return 0
        fi
        sleep 2
    done

    test_fail "BucketClaim cleanup: shadow GarageBucket still exists"
    return 1
}

# ============================================================================
# Main
# ============================================================================

echo "============================================"
echo "  Garage Operator COSI E2E Tests"
echo "============================================"
echo ""

# Create Kind cluster
log_info "Creating kind cluster '$CLUSTER_NAME' with image $KIND_NODE_IMAGE..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
kind create cluster --name "$CLUSTER_NAME" --image "$KIND_NODE_IMAGE" --wait 120s

# Build and load operator image
if [ "$SKIP_BUILD" = false ]; then
    log_info "Building operator image..."
    cd "$ROOT_DIR"
    docker build -t garage-operator:cosi-e2e .
fi

log_info "Loading operator image into kind..."
kind load docker-image garage-operator:cosi-e2e --name "$CLUSTER_NAME"

# Load COSI sidecar image
# Pull for linux/amd64 explicitly to avoid multi-arch issues with kind load
log_info "Pulling and loading COSI sidecar image..."
docker pull --platform linux/amd64 gcr.io/k8s-staging-sig-storage/objectstorage-sidecar:latest || true
kind load docker-image gcr.io/k8s-staging-sig-storage/objectstorage-sidecar:latest --name "$CLUSTER_NAME" || log_warn "Failed to preload sidecar image, kind will pull it"

# Install COSI CRDs
log_info "Installing COSI CRDs..."
for crd in bucketclaims bucketaccesses bucketclasses bucketaccessclasses buckets; do
    kubectl apply -f "https://raw.githubusercontent.com/kubernetes-sigs/container-object-storage-interface/main/client/config/crd/objectstorage.k8s.io_${crd}.yaml"
done

# Install COSI controller
log_info "Installing COSI controller..."
kubectl apply -k "github.com/kubernetes-sigs/container-object-storage-interface/controller?ref=main"

# Wait for COSI controller to be ready
log_info "Waiting for COSI controller..."
kubectl wait deployment/objectstorage-controller -n container-object-storage-system \
    --for=condition=Available --timeout=120s 2>/dev/null || \
    log_warn "COSI controller may not be available yet, continuing..."

# Create namespace
log_info "Creating namespace '$NAMESPACE'..."
kubectl create ns "$NAMESPACE" 2>/dev/null || true

# Deploy operator with COSI enabled via Helm (includes CRDs)
log_info "Deploying operator with COSI enabled..."
cd "$ROOT_DIR"
make manifests generate
helm install garage-operator "$ROOT_DIR/charts/garage-operator" \
    -n "$NAMESPACE" \
    -f "$ROOT_DIR/charts/garage-operator/values-cosi-e2e.yaml"

# Wait for operator to be ready
log_info "Waiting for operator deployment..."
if ! wait_for_pods_ready "app.kubernetes.io/name=garage-operator" 1 120; then
    log_error "Operator pod failed to start"
    collect_debug_info
    exit 1
fi

# Deploy GarageCluster for COSI tests
log_info "Deploying GarageCluster..."
kubectl apply -f "$ROOT_DIR/config/samples/cosi/garagecluster-e2e.yaml"

# Wait for garage pods
log_info "Waiting for Garage pods..."
if ! wait_for_pods_ready "app.kubernetes.io/name=garage,app.kubernetes.io/managed-by=garage-operator" 1 120; then
    log_error "Garage pods failed to start"
    collect_debug_info
    exit 1
fi

# Wait for cluster to be Running
log_info "Waiting for GarageCluster to be Running..."
if ! check_resource_phase "garagecluster" "garage" "Running" 120; then
    log_error "GarageCluster failed to reach Running phase"
    collect_debug_info
    exit 1
fi

echo ""
echo "============================================"
echo "  Running COSI Tests"
echo "============================================"
echo ""

# Run tests
test_cosi_sidecar_running || true
test_garage_cluster_ready || true
test_bucket_claim_bound || true
test_shadow_bucket_created || true
test_bucket_access_credentials || true
test_shadow_key_created || true
test_bucket_access_cleanup || true
test_bucket_claim_cleanup || true

# Print summary
echo ""
echo "============================================"
echo "  COSI E2E Test Results"
echo "============================================"
echo -e "  ${GREEN}Passed:  $TESTS_PASSED${NC}"
echo -e "  ${RED}Failed:  $TESTS_FAILED${NC}"
echo -e "  ${YELLOW}Skipped: $TESTS_SKIPPED${NC}"
echo "============================================"

if [ "$TESTS_FAILED" -gt 0 ]; then
    collect_debug_info
    exit 1
fi

log_info "All COSI E2E tests passed!"
