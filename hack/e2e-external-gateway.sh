#!/bin/bash
set -euo pipefail

# E2E test: K8s gateway cluster connecting to an external (Docker) Garage node.
# This validates the bidirectional ConnectNode fix — the external cluster must
# see the K8s gateway as online, not just the other way around.
#
# Network topology:
#   Kind pods (10.244.0.0/16) — MASQUERADE through kind node → Garage container (172.30.0.200:3901)
#   Garage container (172.30.0.200) → kind node NodePort (172.30.0.x:30901) → gateway pod
#
# Usage: ./hack/e2e-external-gateway.sh [--no-cleanup] [--skip-build]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

CLUSTER_NAME="garage-ext-gw-e2e"
NAMESPACE="garage-operator-system"
TEST_NAMESPACE="garage-ext-gw-test"
DOCKER_NETWORK="garage-ext-gw-net"
GARAGE_CONTAINER="${CLUSTER_NAME}-external-garage"
GARAGE_IMAGE="dxflrs/garage:v2.2.0"

# Static IP for the external Garage container on the Docker bridge network.
# Far from the typical range kind nodes get (.1–.50) to avoid collision.
GARAGE_STATIC_IP="172.30.0.200"
GARAGE_RPC_PORT=3901
GARAGE_ADMIN_PORT=3903
GARAGE_ADMIN_HOST_PORT=39030  # host port for the test to query directly
GATEWAY_RPC_NODEPORT=30901

TIMEOUT=180

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

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

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

TMPDIR_GARAGE=""

cleanup() {
    if [ "$CLEANUP" = true ]; then
        log_info "Cleaning up..."
        docker rm -f "$GARAGE_CONTAINER" 2>/dev/null || true
        kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
        docker network rm "$DOCKER_NETWORK" 2>/dev/null || true
        [ -n "$TMPDIR_GARAGE" ] && rm -rf "$TMPDIR_GARAGE"
    else
        log_warn "Skipping cleanup. Resources still running:"
        log_warn "  docker rm -f $GARAGE_CONTAINER"
        log_warn "  kind delete cluster --name $CLUSTER_NAME"
        log_warn "  docker network rm $DOCKER_NETWORK"
    fi
}
trap cleanup EXIT

# ============================================================================
# Setup
# ============================================================================

cd "$ROOT_DIR"

RPC_SECRET=$(openssl rand -hex 32)
EXTERNAL_ADMIN_TOKEN="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

log_info "=== Step 1: Docker bridge network ==="
docker network rm "$DOCKER_NETWORK" 2>/dev/null || true
docker network create --subnet "172.30.0.0/24" "$DOCKER_NETWORK"

log_info "=== Step 2: Kind cluster ==="
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
cat <<EOF | kind create cluster --name "$CLUSTER_NAME" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: "10.244.0.0/16"
  serviceSubnet: "10.96.0.0/16"
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: ${GATEWAY_RPC_NODEPORT}
    hostPort: 0
    protocol: TCP
EOF

log_info "=== Step 3: Connect kind node to Docker network ==="
docker network connect "$DOCKER_NETWORK" "${CLUSTER_NAME}-control-plane"

KIND_NODE_DOCKER_IP=$(docker inspect \
    -f "{{with index .NetworkSettings.Networks \"${DOCKER_NETWORK}\"}}{{.IPAddress}}{{end}}" \
    "${CLUSTER_NAME}-control-plane")
log_info "Kind node Docker IP: $KIND_NODE_DOCKER_IP"

GATEWAY_RPC_PUBLIC_ADDR="${KIND_NODE_DOCKER_IP}:${GATEWAY_RPC_NODEPORT}"

# Allow pods (10.244.0.0/16) to forward traffic to/from the Docker bridge (172.30.0.0/24).
# Without these rules, iptables FORWARD chain drops pod→external traffic.
# Also ensure MASQUERADE so the Garage container can route replies back.
log_info "Setting up pod→Docker bridge forwarding rules..."
docker exec "${CLUSTER_NAME}-control-plane" sysctl -w net.ipv4.ip_forward=1
docker exec "${CLUSTER_NAME}-control-plane" iptables -A FORWARD -s 10.244.0.0/16 -d 172.30.0.0/24 -j ACCEPT
docker exec "${CLUSTER_NAME}-control-plane" iptables -A FORWARD -s 172.30.0.0/24 -d 10.244.0.0/16 -j ACCEPT
docker exec "${CLUSTER_NAME}-control-plane" iptables -t nat -A POSTROUTING -s 10.244.0.0/16 -d 172.30.0.0/24 -j MASQUERADE

log_info "=== Step 4: External Garage container ==="
TMPDIR_GARAGE=$(mktemp -d)
mkdir -p "$TMPDIR_GARAGE/meta" "$TMPDIR_GARAGE/data"

cat > "$TMPDIR_GARAGE/garage.toml" <<EOF
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
replication_factor = 1
rpc_bind_addr = "0.0.0.0:${GARAGE_RPC_PORT}"
rpc_public_addr = "${GARAGE_STATIC_IP}:${GARAGE_RPC_PORT}"
rpc_secret = "${RPC_SECRET}"

[s3_api]
s3_region = "us-east-1"
api_bind_addr = "0.0.0.0:3900"
root_domain = ".s3.local"

[admin]
api_bind_addr = "0.0.0.0:${GARAGE_ADMIN_PORT}"
admin_token = "${EXTERNAL_ADMIN_TOKEN}"
EOF

docker run -d \
    --name "$GARAGE_CONTAINER" \
    --network "$DOCKER_NETWORK" \
    --ip "$GARAGE_STATIC_IP" \
    -v "$TMPDIR_GARAGE/garage.toml:/etc/garage.toml:ro" \
    -v "$TMPDIR_GARAGE/meta:/var/lib/garage/meta" \
    -v "$TMPDIR_GARAGE/data:/var/lib/garage/data" \
    -p "127.0.0.1:${GARAGE_ADMIN_HOST_PORT}:${GARAGE_ADMIN_PORT}" \
    "$GARAGE_IMAGE" \
    /garage server

# Verify the container actually started (exits immediately on bad config)
sleep 2
if ! docker inspect --format='{{.State.Running}}' "$GARAGE_CONTAINER" | grep -q true; then
    log_error "External Garage container exited immediately — config error?"
    docker logs "$GARAGE_CONTAINER" 2>&1 | tail -20
    exit 1
fi

# Wait for external Garage admin API to be ready
log_info "Waiting for external Garage admin API..."
end=$((SECONDS + 90))
while [ $SECONDS -lt $end ]; do
    if curl -sf -H "Authorization: Bearer ${EXTERNAL_ADMIN_TOKEN}" \
        "http://localhost:${GARAGE_ADMIN_HOST_PORT}/v2/GetClusterHealth" >/dev/null 2>&1; then
        log_info "External Garage is ready"
        break
    fi
    sleep 2
done
if ! curl -sf -H "Authorization: Bearer ${EXTERNAL_ADMIN_TOKEN}" \
    "http://localhost:${GARAGE_ADMIN_HOST_PORT}/v2/GetClusterHealth" >/dev/null 2>&1; then
    log_error "External Garage admin API never became ready. Container logs:"
    docker logs "$GARAGE_CONTAINER" 2>&1 | tail -30
    exit 1
fi

# Apply layout so the external Garage node is active
log_info "Applying initial layout on external Garage..."
EXTERNAL_NODE_ID=$(curl -sf \
    -H "Authorization: Bearer ${EXTERNAL_ADMIN_TOKEN}" \
    "http://localhost:${GARAGE_ADMIN_HOST_PORT}/v2/GetClusterStatus" | \
    python3 -c "import sys,json; nodes=json.load(sys.stdin)['nodes']; print(nodes[0]['id'])" 2>/dev/null || true)
log_info "External Garage node ID: ${EXTERNAL_NODE_ID:0:16}..."

if [ -n "$EXTERNAL_NODE_ID" ]; then
    curl -sf -X POST \
        -H "Authorization: Bearer ${EXTERNAL_ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        "http://localhost:${GARAGE_ADMIN_HOST_PORT}/v2/UpdateClusterLayout" \
        -d "[{\"id\":\"${EXTERNAL_NODE_ID}\",\"zone\":\"external\",\"capacity\":1073741824}]" >/dev/null || true
    curl -sf -X POST \
        -H "Authorization: Bearer ${EXTERNAL_ADMIN_TOKEN}" \
        "http://localhost:${GARAGE_ADMIN_HOST_PORT}/v2/ApplyClusterLayout" \
        -d '{"version":1}' >/dev/null || true
fi

log_info "=== Step 5: Build operator image ==="
if [ "$SKIP_BUILD" = false ]; then
    docker build -t garage-operator:e2e .
fi
kind load docker-image garage-operator:e2e --name "$CLUSTER_NAME"

log_info "=== Step 6: Deploy operator ==="
helm install garage-operator charts/garage-operator \
    --namespace "$NAMESPACE" \
    --create-namespace \
    -f charts/garage-operator/values-e2e.yaml \
    --wait --timeout 120s

log_info "=== Step 7: Run Ginkgo tests ==="
export EXTERNAL_GARAGE_OPERATOR_ENDPOINT="http://${GARAGE_STATIC_IP}:${GARAGE_ADMIN_PORT}"
export EXTERNAL_GARAGE_HOST_ENDPOINT="http://localhost:${GARAGE_ADMIN_HOST_PORT}"
export EXTERNAL_GARAGE_TOKEN="${EXTERNAL_ADMIN_TOKEN}"
export EXTERNAL_RPC_SECRET="${RPC_SECRET}"
export EXTERNAL_GARAGE_RPC_ADDR="${GARAGE_STATIC_IP}:${GARAGE_RPC_PORT}"
export GATEWAY_RPC_PUBLIC_ADDR="${GATEWAY_RPC_PUBLIC_ADDR}"
export GATEWAY_RPC_NODEPORT="${GATEWAY_RPC_NODEPORT}"
export GATEWAY_KIND_NODE_IP="${KIND_NODE_DOCKER_IP}"
export E2E_TEST_NAMESPACE="${TEST_NAMESPACE}"
export E2E_SKIP_SUITE_SETUP="true"
export CERT_MANAGER_INSTALL_SKIP="true"

go test -tags=e2e ./test/e2e/ -v -ginkgo.v \
    -ginkgo.label-filter=external-gateway \
    -timeout 10m
