#!/usr/bin/env bash
# Setup local development environment for garage-operator
# Usage: ./hack/setup-dev.sh [--reset]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=hack/e2e-common.sh
source "$SCRIPT_DIR/e2e-common.sh"
KIND_CLUSTER_NAME="garage-operator-dev"
KIND_CONFIG="${SCRIPT_DIR}/kind-config.yaml"
IMG="garage-operator:dev"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_dependencies() {
    log_info "Checking dependencies..."
    local missing=()

    command -v kind >/dev/null 2>&1 || missing+=("kind")
    command -v kubectl >/dev/null 2>&1 || missing+=("kubectl")
    command -v docker >/dev/null 2>&1 || missing+=("docker")
    command -v go >/dev/null 2>&1 || missing+=("go")
    command -v timeout >/dev/null 2>&1 || missing+=("timeout")

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        echo "Please install:"
        echo "  - kind: https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
        echo "  - kubectl: https://kubernetes.io/docs/tasks/tools/"
        echo "  - docker: https://docs.docker.com/get-docker/"
        echo "  - go: https://go.dev/doc/install"
        exit 1
    fi
    log_info "All dependencies found"
}

create_cluster() {
    local clusters
    if ! clusters=$(kind get clusters 2>/dev/null); then
        log_error "Could not enumerate Kind clusters"
        return 1
    fi
    if grep -Fqx -- "$KIND_CLUSTER_NAME" <<<"$clusters"; then
        log_info "Kind cluster '${KIND_CLUSTER_NAME}' already exists"
        kubectl cluster-info --context "kind-${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || {
            log_warn "Cluster exists but unreachable, recreating..."
            kind delete cluster --name "${KIND_CLUSTER_NAME}"
            kind create cluster --config "${KIND_CONFIG}"
        }
    else
        log_info "Creating kind cluster '${KIND_CLUSTER_NAME}'..."
        kind create cluster --config "${KIND_CONFIG}"
    fi

    # Set kubectl context
    kubectl config use-context "kind-${KIND_CLUSTER_NAME}"
    log_info "Waiting for nodes to be ready..."
    kubectl wait --for=condition=Ready nodes --all --timeout=120s
}

build_and_load_image() {
    log_info "Building operator image..."
    cd "${PROJECT_ROOT}"

    # Build the image
    docker build -t "${IMG}" .

    # Load into kind
    log_info "Loading image into kind cluster..."
    kind load docker-image "${IMG}" --name "${KIND_CLUSTER_NAME}"
}

install_crds() {
    log_info "Installing CRDs..."
    cd "${PROJECT_ROOT}"
    make install
}

create_test_namespace() {
    log_info "Creating test namespace..."
    kubectl create namespace garage-operator-system --dry-run=client -o yaml | kubectl apply -f -
}

install_cert_manager() {
    if kubectl get crd certificates.cert-manager.io >/dev/null 2>&1; then
        log_info "cert-manager already installed"
        return
    fi
    log_info "Installing cert-manager (required for webhook serving certs)..."
    "${PROJECT_ROOT}/hack/install-cert-manager.sh" "kind-${KIND_CLUSTER_NAME}"
}

deploy_operator() {
    log_info "Deploying operator..."
    cd "${PROJECT_ROOT}"

    # Update kustomization to use local image
    cd config/manager
    kustomize edit set image controller="${IMG}"
    cd "${PROJECT_ROOT}"

    # CRDs inline corev1 types and exceed kubectl's 262KB last-applied-configuration
    # annotation limit. Server-side apply skips that annotation entirely.
    kustomize build config/default | kubectl apply --server-side --force-conflicts -f -

    log_info "Waiting for operator to be ready..."
    if ! kubectl wait --for=condition=Available deployment/garage-operator-controller-manager \
        -n garage-operator-system --timeout=120s; then
        log_error "Operator deployment did not become Available"
        return 1
    fi
    if ! NAMESPACE=garage-operator-system "${PROJECT_ROOT}/hack/wait-for-operator-webhook.sh" \
        "kind-${KIND_CLUSTER_NAME}" garage-operator-webhook-service garage-operator-system 120; then
        log_error "Operator webhook did not become reachable"
        return 1
    fi
}

create_admin_secret() {
    log_info "Creating admin token secret..."
    # Generate a random admin token
    ADMIN_TOKEN=$(openssl rand -hex 32)

    kubectl create secret generic garage-admin-token \
        --from-literal=admin-token="${ADMIN_TOKEN}" \
        -n garage-operator-system \
        --dry-run=client -o yaml | kubectl apply -f -

    echo ""
    log_info "Admin token created. Save this for API access:"
    echo "  Token: ${ADMIN_TOKEN}"
    echo ""
}

print_status() {
    echo ""
    echo "=============================================="
    log_info "Development environment ready!"
    echo "=============================================="
    echo ""
    echo "Cluster: kind-${KIND_CLUSTER_NAME}"
    echo "Context: $(kubectl config current-context)"
    echo ""
    echo "Useful commands:"
    echo "  # View operator logs"
    echo "  kubectl logs -f deployment/garage-operator-controller-manager -n garage-operator-system"
    echo ""
    echo "  # Apply sample resources"
    echo "  kubectl apply -f config/samples/"
    echo ""
    echo "  # Run operator locally (for debugging)"
    echo "  make run"
    echo ""
    echo "  # Port mappings (when using NodePort services):"
    echo "    S3 API:    localhost:3900"
    echo "    Admin API: localhost:3903"
    echo "    Web:       localhost:3902"
    echo ""
    echo "  # Cleanup"
    echo "  make dev-down"
    echo ""
}

reset_cluster() {
    log_warn "Resetting cluster..."
    if kind_cluster_is_absent "$KIND_CLUSTER_NAME"; then
        log_info "Kind cluster '${KIND_CLUSTER_NAME}' is already absent"
        return 0
    fi
    if ! kind delete cluster --name "${KIND_CLUSTER_NAME}"; then
        log_error "Failed to delete Kind cluster '${KIND_CLUSTER_NAME}'"
        return 1
    fi
    if ! kind_cluster_is_absent "$KIND_CLUSTER_NAME"; then
        log_error "Could not verify deletion of Kind cluster '${KIND_CLUSTER_NAME}'"
        return 1
    fi
}

main() {
    cd "${PROJECT_ROOT}"

    # Parse arguments
    if [[ "${1:-}" == "--reset" ]]; then
        reset_cluster
    fi

    check_dependencies
    create_cluster
    install_cert_manager
    install_crds
    create_test_namespace
    create_admin_secret
    build_and_load_image
    deploy_operator
    print_status
}

main "$@"
