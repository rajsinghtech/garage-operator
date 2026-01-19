#!/bin/bash
set -euo pipefail

# COSI E2E test script for garage-operator
# Usage: ./hack/e2e-cosi.sh [--no-cleanup] [--skip-build] [--quick]
#
# Uses public COSI images from gcr.io/k8s-staging-sig-storage/

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CLUSTER_NAME="garage-cosi-e2e"
NAMESPACE="garage-operator-system"
TIMEOUT=180

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

CLEANUP=true
SKIP_BUILD=false
QUICK_MODE=false

for arg in "$@"; do
    case $arg in
        --no-cleanup) CLEANUP=false ;;
        --skip-build) SKIP_BUILD=true ;;
        --quick) QUICK_MODE=true ;;
        --help|-h)
            echo "Usage: $0 [--no-cleanup] [--skip-build] [--quick]"
            exit 0
            ;;
    esac
done

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_test() { echo -e "${BLUE}[TEST]${NC} $1"; }
test_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((TESTS_PASSED++)); }
test_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((TESTS_FAILED++)); }
test_skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; ((TESTS_SKIPPED++)); }

cleanup() {
    if [ "$CLEANUP" = true ]; then
        log_info "Cleaning up kind cluster..."
        kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
    fi
}
trap cleanup EXIT

wait_for_pods_ready() {
    local selector=$1 expected_count=$2 timeout=$3
    local end_time=$((SECONDS + timeout))
    while [ $SECONDS -lt $end_time ]; do
        local ready=$(kubectl get pods -n "$NAMESPACE" -l "$selector" -o jsonpath='{range .items[*]}{.status.containerStatuses[0].ready}{"\n"}{end}' 2>/dev/null | grep -c "true" || true)
        [ "${ready:-0}" -ge "$expected_count" ] && return 0
        sleep 2
    done
    return 1
}

# ============================================================================
# COSI Tests
# ============================================================================

test_cosi_crds() {
    log_test "Testing COSI CRDs installed..."
    for crd in bucketclaims bucketaccesses bucketclasses bucketaccessclasses buckets; do
        kubectl get crd "${crd}.objectstorage.k8s.io" &>/dev/null || { test_fail "Missing CRD: $crd"; return 1; }
    done
    test_pass "All COSI CRDs installed"
}

test_bucketclass() {
    log_test "Testing BucketClass creation..."
    cat <<EOF | kubectl apply -f -
apiVersion: objectstorage.k8s.io/v1alpha2
kind: BucketClass
metadata:
  name: garage-standard
spec:
  driverName: garage.rajsingh.info
  deletionPolicy: Delete
  parameters:
    clusterRef: garage
    clusterNamespace: $NAMESPACE
EOF
    sleep 3
    kubectl get bucketclass garage-standard &>/dev/null && test_pass "BucketClass created" || test_fail "BucketClass failed"
}

test_bucketaccessclass() {
    log_test "Testing BucketAccessClass creation..."
    cat <<EOF | kubectl apply -f -
apiVersion: objectstorage.k8s.io/v1alpha2
kind: BucketAccessClass
metadata:
  name: garage-readwrite
spec:
  driverName: garage.rajsingh.info
  authenticationType: Key
  parameters:
    clusterRef: garage
    clusterNamespace: $NAMESPACE
EOF
    sleep 3
    kubectl get bucketaccessclass garage-readwrite &>/dev/null && test_pass "BucketAccessClass created" || test_fail "BucketAccessClass failed"
}

test_bucketclaim() {
    log_test "Testing BucketClaim provisioning..."
    cat <<EOF | kubectl apply -f -
apiVersion: objectstorage.k8s.io/v1alpha2
kind: BucketClaim
metadata:
  name: test-bucket
  namespace: default
spec:
  bucketClassName: garage-standard
  protocols: [S3]
EOF
    local end=$((SECONDS + 120))
    while [ $SECONDS -lt $end ]; do
        [ "$(kubectl get bucketclaim test-bucket -n default -o jsonpath='{.status.readyToUse}' 2>/dev/null)" = "true" ] && { test_pass "BucketClaim provisioned"; return 0; }
        sleep 5
    done
    test_fail "BucketClaim timeout"
}

test_bucketaccess() {
    log_test "Testing BucketAccess credentials..."
    cat <<EOF | kubectl apply -f -
apiVersion: objectstorage.k8s.io/v1alpha2
kind: BucketAccess
metadata:
  name: test-access
  namespace: default
spec:
  bucketAccessClassName: garage-readwrite
  protocol: S3
  bucketClaims:
    - bucketClaimName: test-bucket
      accessSecretName: test-creds
      accessMode: ReadWrite
EOF
    local end=$((SECONDS + 120))
    while [ $SECONDS -lt $end ]; do
        [ "$(kubectl get bucketaccess test-access -n default -o jsonpath='{.status.readyToUse}' 2>/dev/null)" = "true" ] && { test_pass "BucketAccess credentials created"; return 0; }
        sleep 5
    done
    test_fail "BucketAccess timeout"
}

print_summary() {
    echo ""
    echo "=============================================="
    echo "           COSI TEST SUMMARY"
    echo "=============================================="
    echo -e "  ${GREEN}PASSED:${NC}  $TESTS_PASSED"
    echo -e "  ${RED}FAILED:${NC}  $TESTS_FAILED"
    echo -e "  ${YELLOW}SKIPPED:${NC} $TESTS_SKIPPED"
    echo "=============================================="
    [ $TESTS_FAILED -gt 0 ] && return 1 || return 0
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "Starting COSI E2E tests"
    cd "$ROOT_DIR"

    # Create kind cluster
    log_info "=== Creating kind cluster ==="
    kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
    kind create cluster --name "$CLUSTER_NAME" --wait 60s

    # Build operator image
    if [ "$SKIP_BUILD" = false ]; then
        log_info "=== Building operator image ==="
        docker build -t garage-operator:cosi-e2e .
    fi

    # Load operator image into kind
    log_info "=== Loading operator image into kind ==="
    kind load docker-image garage-operator:cosi-e2e --name "$CLUSTER_NAME"

    # Install COSI CRDs
    log_info "=== Installing COSI CRDs ==="
    for crd in bucketclaims bucketaccesses bucketclasses bucketaccessclasses buckets; do
        kubectl apply -f "https://raw.githubusercontent.com/kubernetes-sigs/container-object-storage-interface/main/client/config/crd/objectstorage.k8s.io_${crd}.yaml" || true
    done

    # Deploy COSI controller (using public image from gcr.io)
    log_info "=== Deploying COSI controller ==="
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: container-object-storage-system
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cosi-controller-sa
  namespace: container-object-storage-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cosi-controller-role
rules:
- apiGroups: ["objectstorage.k8s.io"]
  resources: ["*"]
  verbs: ["*"]
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cosi-controller-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cosi-controller-role
subjects:
- kind: ServiceAccount
  name: cosi-controller-sa
  namespace: container-object-storage-system
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cosi-controller
  namespace: container-object-storage-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cosi-controller
  template:
    metadata:
      labels:
        app: cosi-controller
    spec:
      serviceAccountName: cosi-controller-sa
      containers:
      - name: controller
        image: gcr.io/k8s-staging-sig-storage/objectstorage-controller:latest
        imagePullPolicy: IfNotPresent
EOF
    kubectl rollout status deployment -n container-object-storage-system cosi-controller --timeout=120s

    # Deploy operator via Helm with values file
    log_info "=== Deploying operator via Helm ==="
    helm install garage-operator charts/garage-operator \
        --namespace "$NAMESPACE" \
        --create-namespace \
        -f charts/garage-operator/values-cosi-e2e.yaml \
        --wait --timeout 120s

    # Create GarageCluster
    log_info "=== Creating GarageCluster ==="
    kubectl create secret generic garage-admin-token -n "$NAMESPACE" --from-literal=admin-token="test-$(date +%s)"
    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: garage
  namespace: $NAMESPACE
spec:
  replicas: 3
  zone: test
  replication:
    factor: 3
  storage:
    data:
      size: 1Gi
  network:
    rpcBindPort: 3901
    service:
      type: ClusterIP
  admin:
    enabled: true
    bindPort: 3903
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
EOF

    # Wait for Garage pods
    log_info "=== Waiting for Garage pods ==="
    wait_for_pods_ready "app.kubernetes.io/instance=garage" 3 "$TIMEOUT" || {
        log_error "Garage pods failed to start"
        kubectl logs deployment/garage-operator -n "$NAMESPACE" --tail=50
        exit 1
    }
    sleep 30  # Allow time for cluster initialization

    # Run COSI tests
    log_info "=========================================="
    log_info "         RUNNING COSI TESTS"
    log_info "=========================================="

    test_cosi_crds || true
    test_bucketclass || true
    test_bucketaccessclass || true
    test_bucketclaim || true
    test_bucketaccess || true

    print_summary
}

main "$@"
