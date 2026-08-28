#!/bin/bash
set -euo pipefail

# Quick test script for development iterations
# Assumes kind cluster already exists. Use e2e-test.sh for full test.
# Usage: ./hack/quick-test.sh [cluster-name]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=hack/e2e-common.sh
source "$SCRIPT_DIR/e2e-common.sh"
CLUSTER_NAME="${1:-garage-test}"
NAMESPACE="garage-operator-system"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cd "$ROOT_DIR"

# Check cluster exists
if ! kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    log_error "Kind cluster '$CLUSTER_NAME' not found"
    log_info "Available clusters: $(kind get clusters 2>/dev/null | tr '\n' ' ')"
    log_info "Run ./hack/e2e-test.sh for full test with cluster creation"
    exit 1
fi

# Switch context
kubectl config use-context "kind-${CLUSTER_NAME}"

log_info "=== Quick Test: Rebuilding and redeploying operator ==="

# Build image
log_info "Building operator image..."
docker build -t garage-operator:dev . -q

# Load into kind
log_info "Loading image into kind cluster..."
kind load docker-image garage-operator:dev --name "$CLUSTER_NAME"

# Restart operator deployment to pick up new image
log_info "Restarting operator..."
kubectl rollout restart deployment/garage-operator -n "$NAMESPACE" 2>/dev/null || {
    log_warn "Operator deployment not found, deploying fresh via Helm..."

    # Deploy operator using Helm chart (includes CRDs)
    helm upgrade --install garage-operator charts/garage-operator \
        --namespace "$NAMESPACE" \
        --create-namespace \
        -f charts/garage-operator/values-dev.yaml \
        --wait --timeout 120s

    # Create admin token secret if needed
    kubectl get secret garage-admin-token -n "$NAMESPACE" 2>/dev/null || \
        kubectl create secret generic garage-admin-token -n "$NAMESPACE" --from-literal=admin-token="quick-test-token"
}

# Wait for rollout
log_info "Waiting for operator to be ready..."
kubectl rollout status deployment/garage-operator -n "$NAMESPACE" --timeout=60s

# Apply test resources if not present
if ! kubectl get garagecluster garage -n "$NAMESPACE" 2>/dev/null; then
    log_info "Applying test resources..."
    kubectl apply -f hack/test-resources.yaml
fi

# Wait for the observed reconciliation state instead of assuming a fixed
# controller delay. This also makes a slow image pull or API server visible as
# a real timeout rather than a misleading status snapshot.
log_info "Waiting for reconciliation..."
kubectl wait --for=jsonpath='{.status.phase}'=Running \
    garagecluster/garage -n "$NAMESPACE" --timeout=120s
kubectl wait --for=condition=Ready \
    pod -l garage.rajsingh.info/cluster=garage -n "$NAMESPACE" --timeout=120s

# Show status
log_info "=== Current Status ==="
kubectl get pods -n "$NAMESPACE"
echo ""
kubectl get garagecluster,garagebucket,garagekey -n "$NAMESPACE"

# Check health
health=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.health.status}' 2>/dev/null || echo "unknown")
phase=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "unknown")

echo ""
if [ "$health" = "healthy" ] && [ "$phase" = "Running" ]; then
    log_info "Cluster is healthy and running!"
else
    log_warn "Cluster status: phase=$phase, health=$health"
fi

# Show recent operator logs
echo ""
log_info "=== Recent Operator Logs ==="
kubectl logs deployment/garage-operator -n "$NAMESPACE" --tail=20
