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
# shellcheck source=hack/e2e-common.sh
source "$SCRIPT_DIR/e2e-common.sh"

CLUSTER_NAME="garage-ext-gw-e2e"
NAMESPACE="garage-operator-system"
TEST_NAMESPACE="garage-ext-gw-test"
DOCKER_NETWORK="garage-ext-gw-net"
GARAGE_CONTAINER="${CLUSTER_NAME}-external-garage"
GARAGE_IMAGE="dxflrs/garage:v2.2.0@sha256:45a61ce3f7c9c24fc23d9ed2b09b27ed560ab87b34605d175d5c588f539c24e4"

# Static IP for the external Garage container on the Docker bridge network.
# Far from the typical range kind nodes get (.1–.50) to avoid collision.
GARAGE_STATIC_IP="172.30.0.200"
GARAGE_RPC_PORT=3901
GARAGE_ADMIN_PORT=3903
GARAGE_ADMIN_HOST_PORT=39030 # host port for the test to query directly
GATEWAY_RPC_NODEPORT=30901

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
        --help | -h)
            echo "Usage: $0 [--no-cleanup] [--skip-build]"
            exit 0
            ;;
    esac
done

E2E_KUBECONFIG_DIR=$(mktemp -d "${TMPDIR:-/tmp}/garage-ext-e2e-kubeconfig.XXXXXX")
export KUBECONFIG="$E2E_KUBECONFIG_DIR/config"
export KIND_CLUSTER="$CLUSTER_NAME"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

TMPDIR_GARAGE=""
CLUSTER_CREATED=false
NETWORK_CREATED=false
GARAGE_CONTAINER_CREATED=false
CLUSTER_UID=""
NETWORK_ID=""
GARAGE_CONTAINER_ID=""

dump_debug_info() {
    local cluster="$1"
    local dir="${E2E_DEBUG_DIR:-/tmp/e2e-debug}"
    mkdir -p "$dir" 2>/dev/null || return 0
    kubectl --context "kind-$cluster" get all -A -o wide >"$dir/${cluster}-resources.txt" 2>&1 || true
    kubectl --context "kind-$cluster" get garagecluster,garagenode,garagebucket,garagekey,garageadmintoken -A -o yaml >"$dir/${cluster}-garage-resources.yaml" 2>&1 || true
    kubectl --context "kind-$cluster" get events -A --sort-by=.lastTimestamp >"$dir/${cluster}-events.txt" 2>&1 || true
    kubectl --context "kind-$cluster" logs deployment/garage-operator -n garage-operator-system --tail=2000 >"$dir/${cluster}-operator.log" 2>&1 || true
    kubectl --context "kind-$cluster" logs deployment/garage-operator -n garage-operator-system --tail=2000 --previous >"$dir/${cluster}-operator-previous.log" 2>&1 || true
    docker logs "$GARAGE_CONTAINER" >"$dir/external-garage.log" 2>&1 || true
}

cleanup() {
    if [ "$CLEANUP" = true ]; then
        local clusters live_uid live_container_id live_network_id cleanup_status=0 cluster_cleanup_complete=false container_cleanup_complete=true
        if ! clusters=$(kind get clusters 2>/dev/null); then
            log_error "Could not enumerate Kind clusters; preserving kubeconfig $KUBECONFIG"
            cleanup_status=1
        elif ! grep -Fqx -- "$CLUSTER_NAME" <<<"$clusters"; then
            if [ "$CLUSTER_CREATED" = true ]; then
                log_warn "Kind cluster '$CLUSTER_NAME' is already absent"
            fi
            cluster_cleanup_complete=true
        elif [ "$CLUSTER_CREATED" = true ]; then
                live_uid=$(kubectl --context "kind-$CLUSTER_NAME" get namespace kube-system \
                    -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
                if [ -n "$CLUSTER_UID" ] && [ "$live_uid" = "$CLUSTER_UID" ]; then
                    dump_debug_info "$CLUSTER_NAME"
                else
                    log_error "Refusing to clean '$CLUSTER_NAME': live kube-system UID does not match this run"
                    cleanup_status=1
                fi
        else
            log_error "Refusing to delete unowned Kind cluster '$CLUSTER_NAME'"
            cleanup_status=1
        fi
        log_info "Cleaning up..."
        if [ "$GARAGE_CONTAINER_CREATED" = true ]; then
            container_cleanup_complete=false
            live_container_id=$(docker inspect --format '{{.Id}}' "$GARAGE_CONTAINER" 2>/dev/null || true)
            if [ -n "$GARAGE_CONTAINER_ID" ] && [ "$live_container_id" = "$GARAGE_CONTAINER_ID" ]; then
                if docker rm -f "$GARAGE_CONTAINER" 2>/dev/null; then
                    container_cleanup_complete=true
                else
                    log_error "Failed to remove Garage container '$GARAGE_CONTAINER'; preserving data at $TMPDIR_GARAGE"
                    cleanup_status=1
                fi
            else
                log_error "Refusing to remove replacement container '$GARAGE_CONTAINER'"
                cleanup_status=1
            fi
        fi
        if [ "$CLUSTER_CREATED" = true ] && [ "$cluster_cleanup_complete" = false ] && \
            [ -n "$CLUSTER_UID" ] && [ -n "$live_uid" ] && [ "$live_uid" = "$CLUSTER_UID" ]; then
            if kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null; then
                if kind_cluster_is_absent "$CLUSTER_NAME"; then
                    cluster_cleanup_complete=true
                else
                    log_error "Kind cluster '$CLUSTER_NAME' still exists or could not be verified absent; preserving kubeconfig $KUBECONFIG"
                    cleanup_status=1
                fi
            else
                log_error "Failed to delete kind cluster '$CLUSTER_NAME'; preserving kubeconfig $KUBECONFIG"
                cleanup_status=1
            fi
        fi
        if [ "$NETWORK_CREATED" = true ]; then
            live_network_id=$(docker network inspect --format '{{.Id}}' "$DOCKER_NETWORK" 2>/dev/null || true)
            if [ -n "$NETWORK_ID" ] && [ "$live_network_id" = "$NETWORK_ID" ]; then
                if ! docker network rm "$DOCKER_NETWORK" 2>/dev/null; then
                    log_error "Failed to remove Docker network '$DOCKER_NETWORK'"
                    cleanup_status=1
                fi
            else
                log_error "Refusing to remove replacement network '$DOCKER_NETWORK'"
                cleanup_status=1
            fi
        fi
        if [ -n "$TMPDIR_GARAGE" ]; then
            if [ "$container_cleanup_complete" = true ]; then
                rm -rf "$TMPDIR_GARAGE" || cleanup_status=1
            else
                log_error "Preserving external Garage data after incomplete container cleanup: $TMPDIR_GARAGE"
            fi
        fi
        if [ "$cluster_cleanup_complete" = true ]; then
            rm -f "$KUBECONFIG"
            rmdir "$E2E_KUBECONFIG_DIR" 2>/dev/null || true
        fi
        return "$cleanup_status"
    else
        log_warn "Skipping cleanup. Resources still running:"
        log_warn "  Kubeconfig: $KUBECONFIG"
        log_warn "  docker rm -f $GARAGE_CONTAINER"
        log_warn "  kind delete cluster --name $CLUSTER_NAME"
        log_warn "  docker network rm $DOCKER_NETWORK"
    fi
}
on_exit() {
    local status=$? cleanup_status=0 port_forward_status=0
    trap - EXIT
    stop_all_port_forwards || port_forward_status=$?
    cleanup || cleanup_status=$?
    if [ "$status" -eq 0 ] && [ "$cleanup_status" -ne 0 ]; then
        status=$cleanup_status
    fi
    if [ "$status" -eq 0 ] && [ "$port_forward_status" -ne 0 ]; then
        status=$port_forward_status
    fi
    exit "$status"
}
trap on_exit EXIT

# ============================================================================
# Setup
# ============================================================================

cd "$ROOT_DIR"

RPC_SECRET=$(openssl rand -hex 32)
EXTERNAL_ADMIN_TOKEN="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

log_info "=== Step 1: Docker bridge network ==="
if docker network inspect "$DOCKER_NETWORK" >/dev/null 2>&1; then
    log_error "Refusing to delete pre-existing Docker network '$DOCKER_NETWORK'"
    exit 1
fi
NETWORK_ID=$(docker network create --subnet "172.30.0.0/24" "$DOCKER_NETWORK")
NETWORK_CREATED=true

log_info "=== Step 2: Kind cluster ==="
if ! kind_cluster_is_absent "$CLUSTER_NAME"; then
    log_error "Refusing to delete pre-existing kind cluster '$CLUSTER_NAME'"
    exit 1
fi
if ! cat <<EOF | kind create cluster --name "$CLUSTER_NAME" --config=- --image "$KIND_NODE_IMAGE" --wait 120s
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
then
    if kind get clusters 2>/dev/null | grep -Fqx -- "$CLUSTER_NAME"; then
        CLUSTER_UID=$(kind_cluster_uid "$CLUSTER_NAME" || true)
        if [ -n "$CLUSTER_UID" ]; then
            CLUSTER_CREATED=true
            log_error "kind create failed after creating '$CLUSTER_NAME'; recorded its ownership for cleanup"
        else
            log_error "kind create failed and left an unproven cluster named '$CLUSTER_NAME'; refusing deletion"
        fi
    else
        log_error "kind create cluster failed before creating '$CLUSTER_NAME'"
    fi
    exit 1
fi
CLUSTER_CREATED=true
CLUSTER_UID=$(kind_cluster_uid "$CLUSTER_NAME" || true)
if [ -z "$CLUSTER_UID" ]; then
    log_error "Could not record exact ownership of '$CLUSTER_NAME'"
    exit 1
fi

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

cat >"$TMPDIR_GARAGE/garage.toml" <<EOF
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

if docker container inspect "$GARAGE_CONTAINER" >/dev/null 2>&1; then
    log_error "Refusing to delete pre-existing Docker container '$GARAGE_CONTAINER'"
    exit 1
fi
GARAGE_CONTAINER_ID=$(docker run -d \
    --name "$GARAGE_CONTAINER" \
    --user "$(id -u):$(id -g)" \
    --network "$DOCKER_NETWORK" \
    --ip "$GARAGE_STATIC_IP" \
    -v "$TMPDIR_GARAGE/garage.toml:/etc/garage.toml:ro" \
    -v "$TMPDIR_GARAGE/meta:/var/lib/garage/meta" \
    -v "$TMPDIR_GARAGE/data:/var/lib/garage/data" \
    -p "127.0.0.1:${GARAGE_ADMIN_HOST_PORT}:${GARAGE_ADMIN_PORT}" \
    "$GARAGE_IMAGE" \
    /garage server)
GARAGE_CONTAINER_CREATED=true

# Verify the container actually started (it exits immediately on bad config).
container_state=""
container_deadline=$((SECONDS + 30))
while [ "$SECONDS" -lt "$container_deadline" ]; do
    container_state=$(docker inspect --format='{{.State.Status}}' "$GARAGE_CONTAINER" 2>/dev/null || true)
    case "$container_state" in
        running)
            break
            ;;
        exited|dead)
            break
            ;;
    esac
    sleep 1
done
if [ "$container_state" != "running" ]; then
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
    "http://localhost:${GARAGE_ADMIN_HOST_PORT}/v2/GetClusterStatus" |
    jq -r '[.nodes[]? | select((.id // "") != "")] | sort_by(.id) | first | .id // empty' 2>/dev/null || true)
log_info "External Garage node ID: ${EXTERNAL_NODE_ID:0:16}..."

if [ -z "$EXTERNAL_NODE_ID" ]; then
    log_error "External Garage returned no node ID; refusing to run without a proven storage node"
    exit 1
fi

# UpdateClusterLayout takes {"roles":[…]}, not a bare array, and a role entry
# must carry `tags` — without either, Garage 400s with "invalid type: map,
# expected a sequence" / "did not match any variant of untagged enum
# NodeRoleChangeEnum" (see UpdateClusterLayoutRequest + NodeAssignedRole in
# ../garage doc/api/garage-admin-v2.json). This used to send a bare array
# under `|| true`, so the external node silently never got a layout.
curl -sf -X POST \
    -H "Authorization: Bearer ${EXTERNAL_ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    "http://localhost:${GARAGE_ADMIN_HOST_PORT}/v2/UpdateClusterLayout" \
    -d "{\"roles\":[{\"id\":\"${EXTERNAL_NODE_ID}\",\"zone\":\"external\",\"capacity\":1073741824,\"tags\":[]}]}" >/dev/null
curl -sf -X POST \
    -H "Authorization: Bearer ${EXTERNAL_ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    "http://localhost:${GARAGE_ADMIN_HOST_PORT}/v2/ApplyClusterLayout" \
    -d '{"version":1}' >/dev/null

log_info "Waiting for the exact external storage role and healthy layout..."
layout_ready=false
end=$((SECONDS + 60))
while [ $SECONDS -lt $end ]; do
    health_json=""
    layout_json=""
    if health_json=$(curl -sf -H "Authorization: Bearer ${EXTERNAL_ADMIN_TOKEN}" \
        "http://localhost:${GARAGE_ADMIN_HOST_PORT}/v2/GetClusterHealth") &&
        grep -q '"status":[[:space:]]*"healthy"' <<<"$health_json" &&
        layout_json=$(curl -sf -H "Authorization: Bearer ${EXTERNAL_ADMIN_TOKEN}" \
            "http://localhost:${GARAGE_ADMIN_HOST_PORT}/v2/GetClusterLayout") &&
        EXTERNAL_NODE_ID="$EXTERNAL_NODE_ID" python3 -c '
import json
import os
import sys

node_id = os.environ["EXTERNAL_NODE_ID"]
roles = json.load(sys.stdin).get("roles", [])
if not any(
    role.get("id") == node_id
    and role.get("zone") == "external"
    and role.get("capacity") == 1073741824
    for role in roles
):
    raise SystemExit(1)
' <<<"$layout_json"; then
        layout_ready=true
        break
    fi
    sleep 2
done
if [ "$layout_ready" != true ]; then
    log_error "External Garage never reported the exact assigned storage role with healthy status"
    curl -sf -H "Authorization: Bearer ${EXTERNAL_ADMIN_TOKEN}" \
        "http://localhost:${GARAGE_ADMIN_HOST_PORT}/v2/GetClusterLayout" 2>/dev/null || true
    exit 1
fi
log_info "External Garage layout applied with the exact storage role and is healthy"

log_info "=== Step 5: Build operator image ==="
if [ "$SKIP_BUILD" = false ]; then
    docker build -t garage-operator:e2e .
fi
kind load docker-image garage-operator:e2e --name "$CLUSTER_NAME"

log_info "=== Step 6: Install cert-manager (required by chart webhooks) ==="
"$ROOT_DIR/hack/install-cert-manager.sh"

log_info "=== Step 7: Deploy operator ==="
helm install garage-operator charts/garage-operator \
    --namespace "$NAMESPACE" \
    --create-namespace \
    -f charts/garage-operator/values-e2e.yaml \
    --wait --timeout 120s

NAMESPACE="$NAMESPACE" "$ROOT_DIR/hack/wait-for-operator-webhook.sh" "kind-$CLUSTER_NAME"

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
