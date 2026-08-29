#!/bin/bash
set -euo pipefail

# Multi-cluster E2E test script for garage-operator
# Tests cross-cluster Garage federation with 2 kind clusters
# Usage: ./hack/e2e-multicluster-test.sh [--no-cleanup] [--skip-build]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=hack/e2e-common.sh
source "$SCRIPT_DIR/e2e-common.sh"

# Cluster names
CLUSTER1_NAME="garage-multi-e2e-1"
CLUSTER2_NAME="garage-multi-e2e-2"
NAMESPACE="garage-operator-system"
DOCKER_NETWORK="garage-multi-e2e-net"
TIMEOUT=180
BUSYBOX_IMAGE="busybox:1.37@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
CLUSTER1_CREATED=false
CLUSTER2_CREATED=false
NETWORK_CREATED=false
FEDERATED_CLUSTER1_CONNECTED=0
FEDERATED_CLUSTER2_CONNECTED=0

# Parse arguments
CLEANUP=true
SKIP_BUILD=false
for arg in "$@"; do
    case $arg in
        --no-cleanup) CLEANUP=false ;;
        --skip-build) SKIP_BUILD=true ;;
        --help|-h)
            echo "Usage: $0 [--no-cleanup] [--skip-build]"
            echo "  --no-cleanup  Don't delete the kind clusters after tests"
            echo "  --skip-build  Skip building the operator image"
            exit 0
            ;;
    esac
done

E2E_KUBECONFIG_DIR=$(mktemp -d "${TMPDIR:-/tmp}/garage-multi-e2e-kubeconfig.XXXXXX")
export KUBECONFIG="$E2E_KUBECONFIG_DIR/config"
CLUSTER1_UID=""
CLUSTER2_UID=""
NETWORK_ID=""

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

dump_debug_info() {
    local cluster="$1"
    local dir="${E2E_DEBUG_DIR:-/tmp/e2e-debug}"
    mkdir -p "$dir" 2>/dev/null || return 0
    kubectl --context "kind-$cluster" get all -A -o wide > "$dir/${cluster}-resources.txt" 2>&1 || true
    kubectl --context "kind-$cluster" get garagecluster,garagenode,garagebucket,garagekey,garageadmintoken -A -o yaml > "$dir/${cluster}-garage-resources.yaml" 2>&1 || true
    kubectl --context "kind-$cluster" get events -A --sort-by=.lastTimestamp > "$dir/${cluster}-events.txt" 2>&1 || true
    kubectl --context "kind-$cluster" logs deployment/garage-operator -n garage-operator-system --tail=2000 > "$dir/${cluster}-operator.log" 2>&1 || true
    kubectl --context "kind-$cluster" logs deployment/garage-operator -n garage-operator-system --tail=2000 --previous > "$dir/${cluster}-operator-previous.log" 2>&1 || true
}

cleanup() {
    if [ "$CLEANUP" = true ]; then
        local existing live_uid live_network_id cleanup_status=0 clusters_cleanup_complete=true kind_enumeration_complete=true
        if ! existing=$(kind get clusters 2>/dev/null); then
            log_error "Could not enumerate Kind clusters; preserving kubeconfig $KUBECONFIG"
            cleanup_status=1
            clusters_cleanup_complete=false
            kind_enumeration_complete=false
        fi
        log_info "Cleaning up kind clusters..."
        if [ "$kind_enumeration_complete" = true ]; then
            if [ "$CLUSTER1_CREATED" = true ]; then
                if ! grep -Fqx -- "$CLUSTER1_NAME" <<<"$existing"; then
                    log_warn "Kind cluster '$CLUSTER1_NAME' is already absent"
                else
                    live_uid=$(kubectl --context "kind-$CLUSTER1_NAME" get namespace kube-system -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
                    if [ -n "$CLUSTER1_UID" ] && [ "$live_uid" = "$CLUSTER1_UID" ]; then
                        dump_debug_info "$CLUSTER1_NAME"
                        if kind delete cluster --name "$CLUSTER1_NAME" 2>/dev/null; then
                            if ! kind_cluster_is_absent "$CLUSTER1_NAME"; then
                                log_error "Kind cluster '$CLUSTER1_NAME' still exists or could not be verified absent"
                                cleanup_status=1
                                clusters_cleanup_complete=false
                            fi
                        else
                            log_error "Failed to delete kind cluster '$CLUSTER1_NAME'"
                            cleanup_status=1
                            clusters_cleanup_complete=false
                        fi
                    else
                        log_error "Refusing to delete replacement cluster '$CLUSTER1_NAME'"
                        cleanup_status=1
                        clusters_cleanup_complete=false
                    fi
                fi
            elif grep -Fqx -- "$CLUSTER1_NAME" <<<"$existing"; then
                log_error "Refusing to delete unowned Kind cluster '$CLUSTER1_NAME'"
                cleanup_status=1
                clusters_cleanup_complete=false
            fi
        fi
        if [ "$kind_enumeration_complete" = true ]; then
            if [ "$CLUSTER2_CREATED" = true ]; then
                if ! grep -Fqx -- "$CLUSTER2_NAME" <<<"$existing"; then
                    log_warn "Kind cluster '$CLUSTER2_NAME' is already absent"
                else
                    live_uid=$(kubectl --context "kind-$CLUSTER2_NAME" get namespace kube-system -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
                    if [ -n "$CLUSTER2_UID" ] && [ "$live_uid" = "$CLUSTER2_UID" ]; then
                        dump_debug_info "$CLUSTER2_NAME"
                        if kind delete cluster --name "$CLUSTER2_NAME" 2>/dev/null; then
                            if ! kind_cluster_is_absent "$CLUSTER2_NAME"; then
                                log_error "Kind cluster '$CLUSTER2_NAME' still exists or could not be verified absent"
                                cleanup_status=1
                                clusters_cleanup_complete=false
                            fi
                        else
                            log_error "Failed to delete kind cluster '$CLUSTER2_NAME'"
                            cleanup_status=1
                            clusters_cleanup_complete=false
                        fi
                    else
                        log_error "Refusing to delete replacement cluster '$CLUSTER2_NAME'"
                        cleanup_status=1
                        clusters_cleanup_complete=false
                    fi
                fi
            elif grep -Fqx -- "$CLUSTER2_NAME" <<<"$existing"; then
                log_error "Refusing to delete unowned Kind cluster '$CLUSTER2_NAME'"
                cleanup_status=1
                clusters_cleanup_complete=false
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
        if [ "$clusters_cleanup_complete" = true ]; then
            rm -f "$KUBECONFIG"
            rmdir "$E2E_KUBECONFIG_DIR" 2>/dev/null || true
        else
            log_error "Preserving kubeconfig after incomplete cluster cleanup: $KUBECONFIG"
        fi
        return "$cleanup_status"
    else
        log_warn "Skipping cleanup. Clusters still running:"
        log_info "  Kubeconfig: $KUBECONFIG"
        log_info "  kind delete cluster --name $CLUSTER1_NAME"
        log_info "  kind delete cluster --name $CLUSTER2_NAME"
        log_info "  docker network rm $DOCKER_NETWORK"
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

use_cluster() {
    local cluster_name=$1
    kubectl config use-context "kind-$cluster_name" >/dev/null
}

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

wait_for_resource_deleted() {
    local resource=$1
    local name=$2
    local timeout=$3
    local namespace=${4:-$NAMESPACE}
    local deadline
    local remaining
    deadline=$(($(date +%s) + timeout))

    while [ "$(date +%s)" -lt "$deadline" ]; do
        if remaining=$(kubectl get "$resource" "$name" -n "$namespace" \
            --ignore-not-found -o name --request-timeout=5s 2>/dev/null); then
            if [ -z "$remaining" ]; then
                return 0
            fi
        fi
        sleep 2
    done

    return 1
}

wait_for_labeled_resources_deleted() {
    local resource=$1
    local selector=$2
    local timeout=$3
    local namespace=${4:-$NAMESPACE}
    local deadline
    local remaining
    deadline=$(($(date +%s) + timeout))

    while [ "$(date +%s)" -lt "$deadline" ]; do
        if remaining=$(kubectl get "$resource" -n "$namespace" -l "$selector" \
            -o name --request-timeout=5s 2>/dev/null); then
            if [ -z "$remaining" ]; then
                return 0
            fi
        fi
        sleep 2
    done

    log_error "Timed out waiting for $resource with selector '$selector' to be deleted"
    kubectl get "$resource" -n "$namespace" -l "$selector" -o wide 2>/dev/null || true
    return 1
}

# The scenarios in this script reuse both Kubernetes clusters for several
# independent Garage stores. Between scenarios, both sites are intentionally
# destroyed as one whole-store operation. Declare Destroy on both parents
# before touching either site, delete API children while the Admin API is still
# live, then remove one Kubernetes site at a time. This is explicit external
# serialization; the in-memory layout coordinator does not lock across the two
# controller managers.
teardown_whole_federated_store() {
    local cluster_label="garage.rajsingh.info/cluster=garage"
    local cluster_name
    local parent
    local resource

    for cluster_name in "$CLUSTER1_NAME" "$CLUSTER2_NAME"; do
        if ! use_cluster "$cluster_name"; then
            log_error "$cluster_name: failed to select Kubernetes context"
            return 1
        fi
        if ! parent=$(kubectl get garagecluster garage -n "$NAMESPACE" \
            --ignore-not-found -o name 2>/dev/null); then
            log_error "$cluster_name: failed to inspect the previous GarageCluster"
            return 1
        fi
        if [ -n "$parent" ]; then
            if ! kubectl patch garagecluster garage -n "$NAMESPACE" --type=merge \
                -p '{"spec":{"deletionPolicy":"Destroy"}}'; then
                log_error "$cluster_name: failed to acknowledge whole-store Destroy"
                return 1
            fi
        fi
    done

    # Finalize resources that call the Admin API before stopping any Garage
    # process. Both clusters still serve the same ring at this point.
    for cluster_name in "$CLUSTER1_NAME" "$CLUSTER2_NAME"; do
        if ! use_cluster "$cluster_name"; then
            log_error "$cluster_name: failed to select Kubernetes context for API-child cleanup"
            return 1
        fi
        if ! kubectl delete garagekey --all -n "$NAMESPACE" --ignore-not-found=true \
            --wait=true --timeout=120s; then
            log_error "$cluster_name: GarageKey cleanup did not complete while the store was live"
            return 1
        fi
        if ! kubectl delete garagebucket --all -n "$NAMESPACE" --ignore-not-found=true \
            --wait=true --timeout=120s; then
            log_error "$cluster_name: GarageBucket cleanup did not complete while the store was live"
            return 1
        fi
    done

    for cluster_name in "$CLUSTER1_NAME" "$CLUSTER2_NAME"; do
        if ! use_cluster "$cluster_name"; then
            log_error "$cluster_name: failed to select Kubernetes context for site teardown"
            return 1
        fi
        if ! kubectl delete garagecluster garage -n "$NAMESPACE" \
            --ignore-not-found=true --wait=false --request-timeout=15s; then
            log_error "$cluster_name: failed to request GarageCluster deletion"
            return 1
        fi
        if ! wait_for_resource_deleted garagecluster garage 300; then
            log_error "$cluster_name: GarageCluster did not finish whole-store Destroy teardown"
            kubectl get garagecluster,garagenode,statefulset,daemonset,deployment,pod,service,configmap,secret,poddisruptionbudget,pvc \
                -n "$NAMESPACE" -o wide 2>/dev/null || true
            return 1
        fi
        # Parent finalization requests child deletion, but Kubernetes owner GC
        # is asynchronous. Do not reuse the stable name "garage" until every
        # old-UID-owned workload and immutable/config-facing resource is gone;
        # otherwise the next scenario can collide with an old Service or
        # content-addressed config object after the parent itself disappeared.
        for resource in \
            garagenode statefulset daemonset deployment replicaset pod \
            service configmap secret poddisruptionbudget; do
            if ! wait_for_labeled_resources_deleted "$resource" "$cluster_label" 180; then
                log_error "$cluster_name: old-store managed resources remained after their parent was deleted"
                return 1
            fi
        done

        # Storage PVCs intentionally default to Retain. Delete only this test
        # store's labeled claims, and only after no Pod can still hold the
        # pvc-protection finalizer. Never issue an unbounded raw PVC deletion.
        if ! kubectl delete pvc -n "$NAMESPACE" -l "$cluster_label" \
            --ignore-not-found=true --wait=false --request-timeout=15s; then
            log_error "$cluster_name: failed to request retained test PVC cleanup"
            return 1
        fi
        if ! wait_for_labeled_resources_deleted pvc "$cluster_label" 180; then
            log_error "$cluster_name: retained test PVC cleanup did not complete"
            return 1
        fi
    done

    return 0
}

kubectl_apply_with_retries() {
    local attempts=${1:-30}
    local delay=${2:-2}
    local tmp
    tmp=$(mktemp)
    cat > "$tmp"

    local output=""
    for ((i = 1; i <= attempts; i++)); do
        if output=$(kubectl apply -f "$tmp" 2>&1); then
            echo "$output"
            rm -f "$tmp"
            return 0
        fi
        log_warn "kubectl apply failed (attempt $i/$attempts): $output"
        sleep "$delay"
    done

    rm -f "$tmp"
    return 1
}

wait_for_pods_ready() {
    local selector=$1
    local expected_count=$2
    local timeout=$3

    log_info "Waiting for $expected_count pods with selector '$selector' to be ready..."
    local end_time=$((SECONDS + timeout))

    while [ $SECONDS -lt $end_time ]; do
        local ready_pods
        if ready_pods=$(ready_active_pod_count "$NAMESPACE" "$selector") && \
            [ "$ready_pods" -ge "$expected_count" ]; then
            log_info "All $expected_count pods are ready"
            return 0
        fi
        sleep 2
    done

    log_error "Timeout waiting for pods"
    kubectl get pods -n "$NAMESPACE" -l "$selector"
    return 1
}

check_resource_phase() {
    local resource_type=$1
    local resource_name=$2
    local expected_phase=$3
    local timeout=$4

    local end_time=$((SECONDS + timeout))

    while [ $SECONDS -lt $end_time ]; do
        local phase
        phase=$(kubectl get "$resource_type" "$resource_name" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
        if [ "$phase" = "$expected_phase" ]; then
            return 0
        fi
        sleep 2
    done
    return 1
}

get_cluster_health() {
    local cluster_name=$1
    kubectl get garagecluster "$cluster_name" -n "$NAMESPACE" \
        -o jsonpath='{.status.health.status}' --request-timeout=5s 2>/dev/null || echo "unknown"
}

get_connected_nodes() {
    local cluster_name=$1
    kubectl get garagecluster "$cluster_name" -n "$NAMESPACE" \
        -o jsonpath='{.status.health.connectedNodes}' --request-timeout=5s 2>/dev/null || echo "0"
}

wait_for_cluster_replicas() {
    local cluster_name=$1
    local expected_replicas=$2
    local timeout=$3
    local phase="" ready=""

    log_info "Waiting for GarageCluster/$cluster_name to be Running with $expected_replicas ready replicas (timeout: ${timeout}s)..."
    local end_time=$((SECONDS + timeout))
    while [ "$SECONDS" -lt "$end_time" ]; do
        local snapshot
        snapshot=$(kubectl get garagecluster "$cluster_name" -n "$NAMESPACE" \
            -o 'jsonpath={.status.phase}{"|"}{.status.readyReplicas}' \
            --request-timeout=5s 2>/dev/null || true)
        IFS='|' read -r phase ready <<< "$snapshot"
        if [ "$phase" = "Running" ] && [ "$ready" = "$expected_replicas" ]; then
            return 0
        fi
        sleep 2
    done

    log_error "GarageCluster/$cluster_name did not converge (phase=${phase:-unknown}, readyReplicas=${ready:-unknown})"
    return 1
}

wait_for_cluster_health_and_nodes() {
    local cluster_name=$1
    local expected_health=$2
    local minimum_connected=$3
    local timeout=$4
    local health="" connected=""

    log_info "Waiting for GarageCluster/$cluster_name health=$expected_health with at least $minimum_connected connected nodes (timeout: ${timeout}s)..."
    local end_time=$((SECONDS + timeout))
    while [ "$SECONDS" -lt "$end_time" ]; do
        local snapshot
        snapshot=$(kubectl get garagecluster "$cluster_name" -n "$NAMESPACE" \
            -o 'jsonpath={.status.health.status}{"|"}{.status.health.connectedNodes}' \
            --request-timeout=5s 2>/dev/null || true)
        IFS='|' read -r health connected <<< "$snapshot"
        if [ "$health" = "$expected_health" ] &&
            [[ "$connected" =~ ^[0-9]+$ ]] && [ "$connected" -ge "$minimum_connected" ]; then
            return 0
        fi
        sleep 3
    done

    log_error "GarageCluster/$cluster_name health did not converge (health=${health:-unknown}, connected=${connected:-unknown})"
    return 1
}

wait_for_federated_peers() {
    local timeout=${1:-180}
    local minimum=${2:-3}
    local end_time=$((SECONDS + timeout))
    local cluster1_health="" cluster2_health=""
    local cluster1_connected=0 cluster2_connected=0

    while [ "$SECONDS" -lt "$end_time" ]; do
        local cluster1_snapshot cluster2_snapshot
        cluster1_snapshot=$(kubectl --context "kind-$CLUSTER1_NAME" get garagecluster garage \
            -n "$NAMESPACE" -o 'jsonpath={.status.health.status}{"|"}{.status.health.connectedNodes}' \
            --request-timeout=5s 2>/dev/null || true)
        cluster2_snapshot=$(kubectl --context "kind-$CLUSTER2_NAME" get garagecluster garage \
            -n "$NAMESPACE" -o 'jsonpath={.status.health.status}{"|"}{.status.health.connectedNodes}' \
            --request-timeout=5s 2>/dev/null || true)
        IFS='|' read -r cluster1_health cluster1_connected <<< "$cluster1_snapshot"
        IFS='|' read -r cluster2_health cluster2_connected <<< "$cluster2_snapshot"
        FEDERATED_CLUSTER1_CONNECTED=${cluster1_connected:-0}
        FEDERATED_CLUSTER2_CONNECTED=${cluster2_connected:-0}
        if [ "$cluster1_health" = "healthy" ] && [ "$cluster2_health" = "healthy" ] &&
            [[ "$cluster1_connected" =~ ^[0-9]+$ ]] && [[ "$cluster2_connected" =~ ^[0-9]+$ ]] && \
            [ "$cluster1_connected" -ge "$minimum" ] && [ "$cluster2_connected" -ge "$minimum" ]; then
            return 0
        fi
        sleep 3
    done
    return 1
}

# Get the Docker container IP for a kind cluster node
get_kind_node_ip() {
    local cluster_name=$1
    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${cluster_name}-control-plane" 2>/dev/null || echo ""
}

# ============================================================================
# Setup Functions
# ============================================================================

setup_docker_network() {
    log_info "Creating shared Docker network: $DOCKER_NETWORK"

    if docker network inspect "$DOCKER_NETWORK" >/dev/null 2>&1; then
        log_error "Refusing to delete pre-existing Docker network '$DOCKER_NETWORK'"
        return 1
    fi

    # Create new network
    NETWORK_ID=$(docker network create "$DOCKER_NETWORK" --driver bridge)
    NETWORK_CREATED=true
}

create_kind_cluster() {
    local cluster_name=$1
    local zone=$2
    local pod_subnet=$3

    log_info "Creating kind cluster: $cluster_name (zone: $zone, podSubnet: $pod_subnet)"

    # Create kind config with unique pod subnet and NodePort mappings for RPC
    if ! cat <<EOF | kind create cluster --name "$cluster_name" --config=- --image "$KIND_NODE_IMAGE" --wait 120s
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: "$pod_subnet"
  serviceSubnet: "10.96.0.0/16"
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30901
    hostPort: 0
    protocol: TCP
EOF
    then
        log_error "kind create failed for '$cluster_name'"
        return 1
    fi

    # Connect kind cluster to shared network. This is required for the explicit
    # pod-network routes below; continuing after a daemon or permission error
    # would make the federation checks fail later with a misleading symptom.
    if ! docker network connect "$DOCKER_NETWORK" "${cluster_name}-control-plane"; then
        log_error "Could not connect ${cluster_name}-control-plane to $DOCKER_NETWORK"
        return 1
    fi
}

# Set up routing between Kind clusters so pods can reach each other
setup_cross_cluster_routes() {
    log_info "Setting up cross-cluster pod network routes..."

    local cluster1_node="${CLUSTER1_NAME}-control-plane"
    local cluster2_node="${CLUSTER2_NAME}-control-plane"

    # Get Docker IPs on shared network
    local cluster1_docker_ip
    cluster1_docker_ip=$(docker inspect -f "{{with index .NetworkSettings.Networks \"$DOCKER_NETWORK\"}}{{.IPAddress}}{{end}}" "$cluster1_node" 2>/dev/null)
    local cluster2_docker_ip
    cluster2_docker_ip=$(docker inspect -f "{{with index .NetworkSettings.Networks \"$DOCKER_NETWORK\"}}{{.IPAddress}}{{end}}" "$cluster2_node" 2>/dev/null)

    if [ -z "$cluster1_docker_ip" ] || [ -z "$cluster2_docker_ip" ]; then
        log_error "Could not get Docker IPs for clusters"
        return 1
    fi

    log_info "Cluster 1 Docker IP: $cluster1_docker_ip, Cluster 2 Docker IP: $cluster2_docker_ip"

    # Enable IP forwarding in both nodes (required for cross-cluster routing)
    if ! docker exec "$cluster1_node" sysctl -w net.ipv4.ip_forward=1 ||
        ! docker exec "$cluster2_node" sysctl -w net.ipv4.ip_forward=1; then
        log_error "Could not enable IP forwarding for cross-cluster routing"
        return 1
    fi

    # Add iptables rules to allow forwarding between pod networks
    if ! docker exec "$cluster1_node" iptables -A FORWARD -s 10.244.0.0/16 -d 10.245.0.0/16 -j ACCEPT ||
        ! docker exec "$cluster1_node" iptables -A FORWARD -s 10.245.0.0/16 -d 10.244.0.0/16 -j ACCEPT ||
        ! docker exec "$cluster2_node" iptables -A FORWARD -s 10.244.0.0/16 -d 10.245.0.0/16 -j ACCEPT ||
        ! docker exec "$cluster2_node" iptables -A FORWARD -s 10.245.0.0/16 -d 10.244.0.0/16 -j ACCEPT; then
        log_error "Could not install cross-cluster forwarding rules"
        return 1
    fi

    # Add routes: cluster1 -> cluster2's pod network (10.245.0.0/16)
    if ! docker exec "$cluster1_node" ip route add 10.245.0.0/16 via "$cluster2_docker_ip"; then
        log_error "Could not add the cluster 1 to cluster 2 pod route"
        return 1
    fi

    # Add routes: cluster2 -> cluster1's pod network (10.244.0.0/16)
    if ! docker exec "$cluster2_node" ip route add 10.244.0.0/16 via "$cluster1_docker_ip"; then
        log_error "Could not add the cluster 2 to cluster 1 pod route"
        return 1
    fi

    log_info "Cross-cluster routes configured"
}

deploy_operator() {
    local cluster_name=$1

    log_info "Deploying operator to cluster: $cluster_name"

    use_cluster "$cluster_name"

    # Load image
    kind load docker-image garage-operator:e2e --name "$cluster_name"

    # Install cert-manager (required by the chart's webhook stack)
    "$ROOT_DIR/hack/install-cert-manager.sh" "kind-$cluster_name"

    # Deploy operator using Helm chart
    helm install garage-operator charts/garage-operator \
        --namespace "$NAMESPACE" \
        --create-namespace \
        -f charts/garage-operator/values-e2e.yaml \
        --wait --timeout 120s

    NAMESPACE="$NAMESPACE" "$ROOT_DIR/hack/wait-for-operator-webhook.sh" "kind-$cluster_name"
}

# Generate a shared RPC secret for both clusters
generate_rpc_secret() {
    # Generate 32-byte hex secret
    openssl rand -hex 32
}

# Patch GarageCluster to add remoteClusters configuration
patch_garage_with_remote_clusters() {
    local cluster_name=$1
    local garage_name=$2
    local remote_name=$3
    local remote_zone=$4
    local remote_endpoint=$5

    log_info "Patching GarageCluster '$garage_name' with remoteClusters pointing to '$remote_name'"
    use_cluster "$cluster_name"

    kubectl patch garagecluster "$garage_name" -n "$NAMESPACE" --type=merge -p "{
  \"spec\": {
    \"remoteClusters\": [
      {
        \"name\": \"$remote_name\",
        \"zone\": \"$remote_zone\",
        \"connection\": {
          \"adminApiEndpoint\": \"$remote_endpoint\",
          \"adminTokenSecretRef\": {
            \"name\": \"garage-admin-token\",
            \"key\": \"admin-token\"
          }
        }
      }
    ]
  }
}"
}

create_garage_cluster() {
    local cluster_name=$1
    local garage_name=$2
    local zone=$3
    local rpc_secret=$4
    local bootstrap_peer=${5:-""}
    local replicas=${6:-2}
    local replication_factor=${7:-2}
    local remote_clusters_yaml=${8:-""}
    local admin_token=${9:-"admin-token-$(date +%s)"}

    log_info "Creating GarageCluster '$garage_name' in '$cluster_name' (zone: $zone, replicas: $replicas, factor: $replication_factor)"

    use_cluster "$cluster_name"

    # Create RPC secret
    kubectl create secret generic garage-rpc-secret -n "$NAMESPACE" \
        --from-literal=rpc-secret="$rpc_secret" 2>/dev/null || true

    # Create admin token (use provided token for cross-cluster authentication)
    kubectl create secret generic garage-admin-token -n "$NAMESPACE" \
        --from-literal=admin-token="$admin_token" 2>/dev/null || true

    # Build bootstrap peers YAML section if remote peer provided
    local bootstrap_peers_yaml=""
    if [ -n "$bootstrap_peer" ]; then
        bootstrap_peers_yaml="    bootstrapPeers:
      - \"$bootstrap_peer\""
        log_info "  Using bootstrap peer: $bootstrap_peer"
    fi

    # Create GarageCluster
    cat <<EOF | kubectl_apply_with_retries
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: $garage_name
  namespace: $NAMESPACE
spec:
  zone: $zone
  image: "dxflrs/garage:v2.2.0@sha256:45a61ce3f7c9c24fc23d9ed2b09b27ed560ab87b34605d175d5c588f539c24e4"
  replication:
    factor: $replication_factor
    consistencyMode: consistent
  storage:
    replicas: $replicas
    data:
      size: 1Gi
    metadata:
      size: 100Mi
  network:
    rpcBindPort: 3901
    rpcSecretRef:
      name: garage-rpc-secret
      key: rpc-secret
$bootstrap_peers_yaml
$remote_clusters_yaml
  admin:
    bindPort: 3903
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
  s3Api:
    bindPort: 3900
    region: garage
EOF
}


# ============================================================================
# Test Functions
# ============================================================================

test_cluster1_creation() {
    log_test "Testing Cluster 1 GarageCluster creation..."

    use_cluster "$CLUSTER1_NAME"

    if wait_for_cluster_replicas garage 2 120; then
        test_pass "Cluster 1: GarageCluster created with 2 ready replicas"
        return 0
    fi
    test_fail "Cluster 1: GarageCluster creation failed"
    return 1
}

test_cluster2_creation() {
    log_test "Testing Cluster 2 GarageCluster creation..."

    use_cluster "$CLUSTER2_NAME"

    if wait_for_cluster_replicas garage 2 120; then
        test_pass "Cluster 2: GarageCluster created with 2 ready replicas"
        return 0
    fi
    test_fail "Cluster 2: GarageCluster creation failed"
    return 1
}

test_cluster1_health() {
    log_test "Testing Cluster 1 health..."

    use_cluster "$CLUSTER1_NAME"

    local health connected
    if wait_for_cluster_health_and_nodes garage healthy 2 120; then
        health=$(get_cluster_health "garage")
        connected=$(get_connected_nodes "garage")
        test_pass "Cluster 1: health=$health, connected=$connected"
        return 0
    fi
    health=$(get_cluster_health "garage")
    connected=$(get_connected_nodes "garage")
    test_fail "Cluster 1: health check failed (health=$health, connected=$connected)"
    return 1
}

test_cluster2_health() {
    log_test "Testing Cluster 2 health..."

    use_cluster "$CLUSTER2_NAME"

    local health connected
    if wait_for_cluster_health_and_nodes garage healthy 2 120; then
        health=$(get_cluster_health "garage")
        connected=$(get_connected_nodes "garage")
        test_pass "Cluster 2: health=$health, connected=$connected"
        return 0
    fi
    health=$(get_cluster_health "garage")
    connected=$(get_connected_nodes "garage")
    test_fail "Cluster 2: health check failed (health=$health, connected=$connected)"
    return 1
}

test_cross_cluster_connectivity() {
    log_test "Testing cross-cluster pod network connectivity..."

    # Get pod IPs from both clusters
    local cluster1_context="kind-$CLUSTER1_NAME"
    local cluster2_context="kind-$CLUSTER2_NAME"
    local cluster1_pod_ip
    local cluster2_pod_ip
    cluster1_pod_ip=$(pod_ip_for_selector "$NAMESPACE" \
        "garage.rajsingh.info/cluster=garage" "$cluster1_context" || true)
    cluster2_pod_ip=$(pod_ip_for_selector "$NAMESPACE" \
        "garage.rajsingh.info/cluster=garage" "$cluster2_context" || true)

    if [ -z "$cluster1_pod_ip" ] || [ -z "$cluster2_pod_ip" ]; then
        test_fail "Cross-cluster connectivity: Could not determine Garage pod IPs (cluster1: $cluster1_pod_ip, cluster2: $cluster2_pod_ip)"
        return 1
    fi

    log_info "  Cluster 1 pod IP: $cluster1_pod_ip (10.244.x.x)"
    log_info "  Cluster 2 pod IP: $cluster2_pod_ip (10.245.x.x)"

    # Deploy temporary test pods for network testing (Garage image doesn't have nc/ping)
    log_info "  Deploying network test pods..."
    if ! kubectl --context "$cluster1_context" delete pod nettest -n "$NAMESPACE" \
        --ignore-not-found=true --wait=true --timeout=60s >/dev/null 2>&1 ||
        ! kubectl --context "$cluster2_context" delete pod nettest -n "$NAMESPACE" \
            --ignore-not-found=true --wait=true --timeout=60s >/dev/null 2>&1; then
        test_fail "Cross-cluster connectivity: Could not remove stale network test pods"
        return 1
    fi

    if ! kubectl --context "$cluster1_context" run nettest --image="$BUSYBOX_IMAGE" \
        --restart=Never -n "$NAMESPACE" -- sleep 300 >/dev/null 2>&1; then
        test_fail "Cross-cluster connectivity: Could not create network test pod in cluster 1"
        return 1
    fi
    if ! kubectl --context "$cluster2_context" run nettest --image="$BUSYBOX_IMAGE" \
        --restart=Never -n "$NAMESPACE" -- sleep 300 >/dev/null 2>&1; then
        kubectl --context "$cluster1_context" delete pod nettest -n "$NAMESPACE" \
            --ignore-not-found=true --wait=false --request-timeout=15s >/dev/null 2>&1 || true
        test_fail "Cross-cluster connectivity: Could not create network test pod in cluster 2"
        return 1
    fi

    # Wait for test pods to be ready
    if ! kubectl --context "$cluster1_context" wait --for=condition=Ready pod/nettest \
        -n "$NAMESPACE" --timeout=30s >/dev/null 2>&1 ||
        ! kubectl --context "$cluster2_context" wait --for=condition=Ready pod/nettest \
            -n "$NAMESPACE" --timeout=30s >/dev/null 2>&1; then
        kubectl --context "$cluster1_context" delete pod nettest -n "$NAMESPACE" \
            --ignore-not-found=true --wait=false --request-timeout=15s >/dev/null 2>&1 || true
        kubectl --context "$cluster2_context" delete pod nettest -n "$NAMESPACE" \
            --ignore-not-found=true --wait=false --request-timeout=15s >/dev/null 2>&1 || true
        test_fail "Cross-cluster connectivity: Network test pods did not become ready in both clusters"
        return 1
    fi

    # Test actual pod-to-pod connectivity
    local c1_to_c2_ok=false
    local c2_to_c1_ok=false

    if kubectl --context "$cluster1_context" exec -n "$NAMESPACE" nettest -- \
        ping -c 1 -W 2 "$cluster2_pod_ip" >/dev/null 2>&1; then
        log_info "  Cluster 1 -> Cluster 2 pod: OK"
        c1_to_c2_ok=true
    else
        log_warn "  Cluster 1 -> Cluster 2 pod: FAILED"
    fi

    if kubectl --context "$cluster2_context" exec -n "$NAMESPACE" nettest -- \
        ping -c 1 -W 2 "$cluster1_pod_ip" >/dev/null 2>&1; then
        log_info "  Cluster 2 -> Cluster 1 pod: OK"
        c2_to_c1_ok=true
    else
        log_warn "  Cluster 2 -> Cluster 1 pod: FAILED"
    fi

    # Cleanup test pods
    kubectl --context "$cluster1_context" delete pod nettest -n "$NAMESPACE" \
        --ignore-not-found=true --wait=false --request-timeout=15s >/dev/null 2>&1 || true
    kubectl --context "$cluster2_context" delete pod nettest -n "$NAMESPACE" \
        --ignore-not-found=true --wait=false --request-timeout=15s >/dev/null 2>&1 || true

    # Each cluster has two local nodes. Federation is converged only when both
    # sides report healthy status and at least one remote peer. Reuse the full
    # readiness barrier instead of giving the peer count a separate short
    # window after the network probe.
    local cluster1_connected=0 cluster2_connected=0
    if wait_for_federated_peers 180 3; then
        cluster1_connected=$FEDERATED_CLUSTER1_CONNECTED
        cluster2_connected=$FEDERATED_CLUSTER2_CONNECTED
    fi

    if [ "$c1_to_c2_ok" = "true" ] && [ "$c2_to_c1_ok" = "true" ] &&
        [[ "$cluster1_connected" =~ ^[0-9]+$ ]] &&
        [[ "$cluster2_connected" =~ ^[0-9]+$ ]] &&
        [ "$cluster1_connected" -gt 2 ] && [ "$cluster2_connected" -gt 2 ]; then
        test_pass "Bidirectional cross-cluster connectivity verified (cluster1 sees $cluster1_connected nodes, cluster2 sees $cluster2_connected nodes)"
        return 0
    fi

    test_fail "Bidirectional cross-cluster connectivity failed (network c1->c2: $c1_to_c2_ok, c2->c1: $c2_to_c1_ok; peers c1: $cluster1_connected, c2: $cluster2_connected)"
    return 1
}

test_automatic_layout_management() {
    log_test "Testing automatic layout management after federation..."

    # Check cluster 1's layout contains nodes from both zones
    use_cluster "$CLUSTER1_NAME"

    if ! start_port_forward svc/garage 3903 "$NAMESPACE" 30; then
        test_fail "Automatic layout: Admin API port-forward did not start"
        return 1
    fi
    local pf_pid=$PORT_FORWARD_PID pf_port=$PORT_FORWARD_PORT pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$pf_port/health" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Automatic layout: Admin API port-forward did not become ready"
        return 1
    fi

    local admin_token
    admin_token=$(kubectl get secret garage-admin-token -n "$NAMESPACE" \
        -o jsonpath='{.data.admin-token}' 2>/dev/null | base64 -d)
    if [ -z "$admin_token" ]; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Automatic layout: Admin token is unavailable"
        return 1
    fi

    # Federation peer discovery and layout application are separate async
    # operations. A successful peer count only proves that the nodes can see
    # each other; the layout may still be at its initial version while the
    # operator stages and applies the remote roles. Wait for the observable
    # layout state instead of sampling that transition once.
    local layout_info=""
    local layout_deadline=$((SECONDS + 180))
    while [ "$SECONDS" -lt "$layout_deadline" ]; do
        if layout_info=$(curl --fail --silent --show-error \
            -H "Authorization: Bearer ${admin_token}" \
            "http://127.0.0.1:$pf_port/v2/GetClusterLayout" 2>/dev/null) &&
            jq -e '.version | type == "number"' >/dev/null 2>&1 <<<"$layout_info" &&
            jq -e '.roles | type == "array"' >/dev/null 2>&1 <<<"$layout_info"; then
            local observed_layout_version observed_node_count observed_zone_count
            observed_layout_version=$(jq -r '.version' <<<"$layout_info")
            observed_node_count=$(jq -r '.roles | length' <<<"$layout_info")
            observed_zone_count=$(jq -r '[.roles[]?.zone // empty] | unique | length' <<<"$layout_info")
            if [[ "$observed_layout_version" =~ ^[0-9]+$ ]] &&
                [[ "$observed_node_count" =~ ^[0-9]+$ ]] &&
                [[ "$observed_zone_count" =~ ^[0-9]+$ ]] &&
                [ "$observed_layout_version" -gt 1 ] &&
                [ "$observed_node_count" -ge 4 ] &&
                [ "$observed_zone_count" -ge 2 ]; then
                break
            fi
            log_info "  Waiting for federated layout (version: $observed_layout_version, nodes: $observed_node_count, zones: $observed_zone_count)"
        fi
        sleep 5
    done

    stop_port_forward "$pf_pid" "$pf_log"

    if ! jq -e '.version | type == "number"' >/dev/null 2>&1 <<<"$layout_info" ||
        ! jq -e '.roles | type == "array"' >/dev/null 2>&1 <<<"$layout_info"; then
        test_fail "Automatic layout: Admin API returned an invalid layout document"
        return 1
    fi

    # Extract zones from layout roles
    local zones
    local node_count
    local layout_version
    local zone_count
    zones=$(jq -r '.roles[]?.zone // empty' <<<"$layout_info" | sort -u | tr '\n' ' ')
    node_count=$(jq -r '.roles | length' <<<"$layout_info")
    layout_version=$(jq -r '.version' <<<"$layout_info")
    zone_count=$(jq -r '[.roles[]?.zone // empty] | unique | length' <<<"$layout_info")

    log_info "  Layout version: $layout_version"
    log_info "  Node count in layout: $node_count"
    log_info "  Zones in layout: $zones"

    # Verify layout version is > 1 (changes were applied). The loop above
    # normally exits only after the complete layout is visible; retain these
    # explicit assertions so a timeout reports the last observed state.
    if [ "$layout_version" -gt 1 ] 2>/dev/null; then
        log_info "  Layout version incremented (federation applied changes)"
    else
        test_fail "Automatic layout: Federated layout did not converge before the deadline (version: $layout_version)"
        return 1
    fi

    # Both zones and all four storage nodes prove that the federated layout was applied.
    if [ "$zone_count" -ge 2 ] && [ "$node_count" -ge 4 ]; then
        test_pass "Automatic layout: Federated layout contains $node_count nodes from $zone_count zones ($zones)"
        return 0
    fi

    test_fail "Automatic layout: Federated layout did not converge to at least four nodes from multiple zones; got $node_count nodes in $zone_count zones ($zones)"
    return 1
}

test_bucket_creation_cluster1() {
    log_test "Testing bucket creation in Cluster 1..."

    use_cluster "$CLUSTER1_NAME"

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: test-bucket
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  globalAlias: test-bucket
EOF

    if check_resource_phase "garagebucket" "test-bucket" "Ready" 60; then
        local bucket_id
        bucket_id=$(kubectl get garagebucket test-bucket -n "$NAMESPACE" -o jsonpath='{.status.bucketId}')
        if [ -n "$bucket_id" ]; then
            test_pass "Cluster 1: Bucket created with ID: $bucket_id"
            return 0
        fi
    fi
    test_fail "Cluster 1: Bucket creation failed"
    return 1
}

test_bucket_creation_cluster2() {
    log_test "Testing bucket creation in Cluster 2..."

    use_cluster "$CLUSTER2_NAME"

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: test-bucket-2
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  globalAlias: test-bucket-2
EOF

    if check_resource_phase "garagebucket" "test-bucket-2" "Ready" 60; then
        local bucket_id
        bucket_id=$(kubectl get garagebucket test-bucket-2 -n "$NAMESPACE" -o jsonpath='{.status.bucketId}')
        if [ -n "$bucket_id" ]; then
            test_pass "Cluster 2: Bucket created with ID: $bucket_id"
            return 0
        fi
    fi
    test_fail "Cluster 2: Bucket creation failed"
    return 1
}

test_key_creation_cluster1() {
    log_test "Testing key creation in Cluster 1..."

    use_cluster "$CLUSTER1_NAME"

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: test-key
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  name: test-key
  bucketPermissions:
    - bucketRef:
        name: test-bucket
      read: true
      write: true
  secretTemplate:
    name: test-credentials
EOF

    if check_resource_phase "garagekey" "test-key" "Ready" 60; then
        local access_key
        access_key=$(kubectl get garagekey test-key -n "$NAMESPACE" -o jsonpath='{.status.accessKeyId}')
        if [ -n "$access_key" ]; then
            test_pass "Cluster 1: Key created with AccessKeyID: $access_key"
            return 0
        fi
    fi
    test_fail "Cluster 1: Key creation failed"
    return 1
}

test_independent_cluster_operations() {
    log_test "Testing independent operations on both clusters..."

    local c1_buckets=0
    local c2_buckets=0

    # Check cluster 1
    use_cluster "$CLUSTER1_NAME"
    c1_buckets=$(kubectl get garagebucket -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l | tr -d ' ')

    # Check cluster 2
    use_cluster "$CLUSTER2_NAME"
    c2_buckets=$(kubectl get garagebucket -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l | tr -d ' ')

    if [ "$c1_buckets" -ge "1" ] && [ "$c2_buckets" -ge "1" ]; then
        test_pass "Both clusters operating independently (cluster1: $c1_buckets buckets, cluster2: $c2_buckets buckets)"
        return 0
    fi
    test_fail "Independent cluster operations failed (cluster1: $c1_buckets buckets, cluster2: $c2_buckets buckets)"
    return 1
}

test_shared_rpc_secret() {
    log_test "Testing shared RPC secret between clusters..."

    # Get RPC secret from cluster 1
    use_cluster "$CLUSTER1_NAME"
    local c1_secret
    c1_secret=$(kubectl get secret garage-rpc-secret -n "$NAMESPACE" -o jsonpath='{.data.rpc-secret}' 2>/dev/null | base64 -d)

    # Get RPC secret from cluster 2
    use_cluster "$CLUSTER2_NAME"
    local c2_secret
    c2_secret=$(kubectl get secret garage-rpc-secret -n "$NAMESPACE" -o jsonpath='{.data.rpc-secret}' 2>/dev/null | base64 -d)

    if [ "$c1_secret" = "$c2_secret" ] && [ -n "$c1_secret" ]; then
        test_pass "RPC secrets match between clusters (length: ${#c1_secret})"
        return 0
    fi
    test_fail "RPC secrets don't match (c1: ${#c1_secret} chars, c2: ${#c2_secret} chars)"
    return 1
}

test_cluster_layout_version() {
    log_test "Testing layout version consistency..."

    local c1_layout
    local c2_layout
    c1_layout=$(kubectl --context "kind-$CLUSTER1_NAME" get garagecluster garage \
        -n "$NAMESPACE" -o jsonpath='{.status.layoutVersion}' 2>/dev/null)
    c2_layout=$(kubectl --context "kind-$CLUSTER2_NAME" get garagecluster garage \
        -n "$NAMESPACE" -o jsonpath='{.status.layoutVersion}' 2>/dev/null)

    if [ -n "$c1_layout" ] && [ "$c1_layout" = "$c2_layout" ]; then
        test_pass "Federated layout versions match (version: $c1_layout)"
        return 0
    fi
    test_fail "Federated layout versions are missing or inconsistent (c1: $c1_layout, c2: $c2_layout)"
    return 1
}

test_key_creation_cluster2() {
    log_test "Testing key creation in Cluster 2..."

    use_cluster "$CLUSTER2_NAME"

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: test-key-2
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  name: test-key-2
  bucketPermissions:
    - bucketRef:
        name: test-bucket-2
      read: true
      write: true
  secretTemplate:
    name: test-credentials-2
EOF

    if check_resource_phase "garagekey" "test-key-2" "Ready" 60; then
        local access_key
        access_key=$(kubectl get garagekey test-key-2 -n "$NAMESPACE" -o jsonpath='{.status.accessKeyId}')
        if [ -n "$access_key" ]; then
            test_pass "Cluster 2: Key created with AccessKeyID: $access_key"
            return 0
        fi
    fi
    test_fail "Cluster 2: Key creation failed"
    return 1
}

# ============================================================================
# Credential Drift Test
# ============================================================================
# This test verifies the fix for credential drift where K8s secrets become
# stale when keys are deleted/recreated in Garage outside the operator.

test_credential_drift() {
    log_test "Testing credential drift detection and sync..."

    use_cluster "$CLUSTER1_NAME"

    # Step 1: Get the current secret value
    local original_secret
    local access_key_id
    original_secret=$(kubectl get secret test-credentials -n "$NAMESPACE" \
        -o jsonpath='{.data.secret-access-key}' 2>/dev/null | base64 -d)
    access_key_id=$(kubectl get garagekey test-key -n "$NAMESPACE" \
        -o jsonpath='{.status.accessKeyId}' 2>/dev/null)

    if [ -z "$original_secret" ] || [ -z "$access_key_id" ]; then
        test_fail "Credential drift: Could not get original credentials (secret: ${#original_secret} chars, keyId: $access_key_id)"
        return 1
    fi

    log_info "  Original secret length: ${#original_secret} chars"
    log_info "  Access key ID: $access_key_id"

    # Step 2: Delete the key directly in Garage via Admin API
    log_info "  Deleting key directly in Garage (simulating external deletion)..."
    local admin_token
    admin_token=$(kubectl get secret garage-admin-token -n "$NAMESPACE" \
        -o jsonpath='{.data.admin-token}' 2>/dev/null | base64 -d)
    if [ -z "$admin_token" ]; then
        test_fail "Credential drift: Admin token is unavailable"
        return 1
    fi

    if ! start_port_forward svc/garage 3903 "$NAMESPACE" 30; then
        test_fail "Credential drift: Admin API port-forward did not start"
        return 1
    fi
    local pf_pid=$PORT_FORWARD_PID pf_port=$PORT_FORWARD_PORT pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$pf_port/health" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Credential drift: Admin API port-forward did not become ready"
        return 1
    fi

    # Delete the key
    local delete_result
    if ! delete_result=$(curl --fail --silent --show-error -X POST \
        -H "Authorization: Bearer ${admin_token}" \
        "http://127.0.0.1:$pf_port/v2/DeleteKey?id=${access_key_id}" 2>/dev/null); then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Credential drift: Garage did not confirm external key deletion"
        return 1
    fi

    log_info "  Delete result: $delete_result"
    stop_port_forward "$pf_pid" "$pf_log"

    # Step 3: Trigger reconciliation by updating the GarageKey annotation
    log_info "  Triggering operator reconciliation..."
    kubectl annotate garagekey test-key -n "$NAMESPACE" "test-trigger=$(date +%s)" --overwrite

    # Step 4: Require affirmative evidence that both the key and its secret rotated.
    local new_access_key_id=""
    local new_secret=""
    local drift_deadline=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$drift_deadline" ]; do
        new_access_key_id=$(kubectl get garagekey test-key -n "$NAMESPACE" \
            -o jsonpath='{.status.accessKeyId}' 2>/dev/null)
        new_secret=$(kubectl get secret test-credentials -n "$NAMESPACE" \
            -o jsonpath='{.data.secret-access-key}' 2>/dev/null | base64 -d)

        if [ -n "$new_access_key_id" ] && [ "$new_access_key_id" != "$access_key_id" ] &&
            [ -n "$new_secret" ] && [ "$new_secret" != "$original_secret" ]; then
            log_info "  New key created with ID: $new_access_key_id"
            test_pass "Credential drift: Operator recreated the key and synchronized new credentials"
            return 0
        fi
        sleep 5
    done

    test_fail "Credential drift: Credentials did not rotate after external deletion (old key: $access_key_id, current key: $new_access_key_id)"
    return 1
}

# ============================================================================
# Key Sync Across Clusters Test
# ============================================================================
# This test verifies that keys created in one cluster work across the
# federated Garage cluster (the key exists in Garage's distributed state).

test_key_sync_across_clusters() {
    log_test "Testing key sync across federated clusters..."

    # Check connected node count - both clusters must see remote nodes
    use_cluster "$CLUSTER1_NAME"
    local c1_connected
    c1_connected=$(get_connected_nodes "garage")
    use_cluster "$CLUSTER2_NAME"
    local c2_connected
    c2_connected=$(get_connected_nodes "garage")

    log_info "  Connected nodes - cluster1: $c1_connected, cluster2: $c2_connected"

    # Federation requires BOTH clusters to see more than their local nodes (2 each)
    if [ "$c1_connected" -le 2 ] || [ "$c2_connected" -le 2 ]; then
        log_warn "  Clusters not fully federated (c1: $c1_connected nodes, c2: $c2_connected nodes)"
        log_warn "  For key sync to work, both clusters must see >2 connected nodes"
        test_fail "Key sync: Clusters not federated (c1: $c1_connected, c2: $c2_connected)"
        return 1
    fi

    # Step 1: Get key info from cluster 1
    use_cluster "$CLUSTER1_NAME"
    local c1_key_id
    c1_key_id=$(kubectl get garagekey test-key -n "$NAMESPACE" -o jsonpath='{.status.accessKeyId}' 2>/dev/null)

    if [ -z "$c1_key_id" ]; then
        test_fail "Key sync: Could not get key ID from cluster 1"
        return 1
    fi

    log_info "  Cluster 1 key ID: $c1_key_id"

    # Step 2: Wait for CRDT propagation with retries
    # Garage uses CRDTs for distributed state - propagation isn't instant
    use_cluster "$CLUSTER2_NAME"
    local c2_admin_token
    c2_admin_token=$(kubectl get secret garage-admin-token -n "$NAMESPACE" -o jsonpath='{.data.admin-token}' 2>/dev/null | base64 -d)

    if ! start_port_forward svc/garage 3903 "$NAMESPACE" 30; then
        test_fail "Key sync: Admin API port-forward did not start"
        return 1
    fi
    local pf_pid=$PORT_FORWARD_PID pf_port=$PORT_FORWARD_PORT pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$pf_port/health" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Key sync: Admin API port-forward did not become ready"
        return 1
    fi

    local found_key_id=""
    local max_attempts=10
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        log_info "  Checking for key in cluster 2 (attempt $attempt/$max_attempts)..."

        # Query the key from cluster 2's Garage instance
        local key_info
        key_info=$(curl -s -H "Authorization: Bearer ${c2_admin_token}" \
            "http://127.0.0.1:$pf_port/v2/GetKeyInfo?id=${c1_key_id}" 2>/dev/null)

        found_key_id=$(echo "$key_info" | jq -r '.accessKeyId // empty' 2>/dev/null)

        if [ "$found_key_id" = "$c1_key_id" ]; then
            stop_port_forward "$pf_pid" "$pf_log"
            test_pass "Key sync: Key created in cluster 1 is visible in cluster 2 (federated state, attempt $attempt)"
            return 0
        fi

        if [ $attempt -lt $max_attempts ]; then
            log_info "  Key not yet visible, waiting for CRDT propagation..."
            sleep 10
        fi
        ((attempt++))
    done

    stop_port_forward "$pf_pid" "$pf_log"

    # Debug: Check the layout to see if nodes from both clusters are included
    log_info "  Debugging layout configuration..."
    if ! start_port_forward svc/garage 3903 "$NAMESPACE" 30; then
        test_fail "Key sync: Admin API port-forward did not start for layout diagnostics"
        return 1
    fi
    pf_pid=$PORT_FORWARD_PID
    pf_port=$PORT_FORWARD_PORT
    pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$pf_port/health" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Key sync: Admin API port-forward did not become ready for layout diagnostics"
        return 1
    fi
    local layout_info
    layout_info=$(curl -s -H "Authorization: Bearer ${c2_admin_token}" \
        "http://127.0.0.1:$pf_port/v2/GetClusterLayout" 2>/dev/null)
    local layout_nodes
    layout_nodes=$(echo "$layout_info" | jq -r '.roles | length // 0' 2>/dev/null)
    log_info "  Layout has $layout_nodes nodes configured"

    # Also check cluster status to see all known nodes
    local status_info
    status_info=$(curl -s -H "Authorization: Bearer ${c2_admin_token}" \
        "http://127.0.0.1:$pf_port/v2/GetClusterStatus" 2>/dev/null)
    local all_known_nodes
    all_known_nodes=$(echo "$status_info" | jq -r '.nodes | length // 0' 2>/dev/null)
    log_info "  Cluster knows about $all_known_nodes nodes total"
    stop_port_forward "$pf_pid" "$pf_log"

    # If key not found after retries, check if federation is actually working
    # by verifying we can at least list keys from cluster 2
    if ! start_port_forward svc/garage 3903 "$NAMESPACE" 30; then
        test_fail "Key sync: Admin API port-forward did not start for key listing"
        return 1
    fi
    pf_pid=$PORT_FORWARD_PID
    pf_port=$PORT_FORWARD_PORT
    pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$pf_port/health" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Key sync: Admin API port-forward did not become ready for key listing"
        return 1
    fi

    local list_result
    list_result=$(curl -s -H "Authorization: Bearer ${c2_admin_token}" \
        "http://127.0.0.1:$pf_port/v2/ListKeys" 2>/dev/null)
    local key_count
    key_count=$(echo "$list_result" | jq -r 'length // 0' 2>/dev/null)

    stop_port_forward "$pf_pid" "$pf_log"

    log_warn "  Cluster 2 sees $key_count keys total"
    log_warn "  Key $c1_key_id not found after $max_attempts attempts"

    test_fail "Key sync: Key from cluster 1 ($c1_key_id) not found in cluster 2 after $max_attempts attempts"
    return 1
}

# ============================================================================
# Credential Validation Test (S3 API)
# ============================================================================
# This test verifies that the credentials in the K8s secret actually work
# for S3 API operations against Garage.

test_credential_validation() {
    log_test "Testing credential validation via S3 API..."

    use_cluster "$CLUSTER1_NAME"

    # Get credentials from the secret
    local access_key
    access_key=$(kubectl get secret test-credentials -n "$NAMESPACE" -o jsonpath='{.data.access-key-id}' 2>/dev/null | base64 -d)
    local secret_key
    secret_key=$(kubectl get secret test-credentials -n "$NAMESPACE" -o jsonpath='{.data.secret-access-key}' 2>/dev/null | base64 -d)

    if [ -z "$access_key" ] || [ -z "$secret_key" ]; then
        test_fail "Credential validation: Could not get credentials from secret"
        return 1
    fi

    log_info "  Testing S3 credentials (access key: $access_key)"

    # Port-forward to S3 API
    if ! start_port_forward svc/garage 3900 "$NAMESPACE" 30; then
        test_fail "Credential validation: S3 port-forward did not start"
        return 1
    fi
    local pf_pid=$PORT_FORWARD_PID pf_port=$PORT_FORWARD_PORT pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$pf_port/" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Credential validation: S3 port-forward did not become ready"
        return 1
    fi

    # Try to list the bucket using AWS CLI (if available) or curl with S3 signature
    # For simplicity, we'll use the Admin API to verify the key is valid
    local admin_token
    admin_token=$(kubectl get secret garage-admin-token -n "$NAMESPACE" -o jsonpath='{.data.admin-token}' 2>/dev/null | base64 -d)

    if ! start_port_forward svc/garage 3903 "$NAMESPACE" 30; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Credential validation: Admin API port-forward did not start"
        return 1
    fi
    local admin_pf_pid=$PORT_FORWARD_PID admin_pf_port=$PORT_FORWARD_PORT admin_pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$admin_pf_pid" "http://127.0.0.1:$admin_pf_port/health" 30 "$admin_pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        stop_port_forward "$admin_pf_pid" "$admin_pf_log"
        test_fail "Credential validation: Admin API port-forward did not become ready"
        return 1
    fi

    # Verify key exists and has correct permissions via Admin API
    local key_info
    key_info=$(curl -s -H "Authorization: Bearer ${admin_token}" \
        "http://127.0.0.1:$admin_pf_port/v2/GetKeyInfo?id=${access_key}" 2>/dev/null)

    stop_port_forward "$pf_pid" "$pf_log"
    stop_port_forward "$admin_pf_pid" "$admin_pf_log"

    local found_key
    found_key=$(echo "$key_info" | jq -r '.accessKeyId // empty' 2>/dev/null)
    local has_bucket
    has_bucket=$(echo "$key_info" | jq -r '.buckets | length' 2>/dev/null)

    if [ "$found_key" = "$access_key" ] && [ "$has_bucket" -gt 0 ]; then
        test_pass "Credential validation: Key is valid and has bucket permissions"
        return 0
    fi

    test_fail "Credential validation: Key validation failed (found: $found_key, buckets: $has_bucket)"
    return 1
}

test_total_node_count() {
    log_test "Testing total node count across clusters..."

    local total_nodes=0

    # Count nodes in cluster 1
    use_cluster "$CLUSTER1_NAME"
    local c1_nodes
    c1_nodes=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.health.storageNodes}' 2>/dev/null || echo "0")

    # Count nodes in cluster 2
    use_cluster "$CLUSTER2_NAME"
    local c2_nodes
    c2_nodes=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.health.storageNodes}' 2>/dev/null || echo "0")

    total_nodes=$((c1_nodes + c2_nodes))

    if [ "$total_nodes" -ge "4" ]; then
        test_pass "Total nodes across clusters: $total_nodes (c1: $c1_nodes, c2: $c2_nodes)"
        return 0
    fi
    test_fail "Insufficient total nodes (total: $total_nodes, c1: $c1_nodes, c2: $c2_nodes)"
    return 1
}

test_admin_api_cluster1() {
    log_test "Testing Admin API in Cluster 1..."

    use_cluster "$CLUSTER1_NAME"

    if ! start_port_forward svc/garage 3903 "$NAMESPACE" 30; then
        test_fail "Cluster 1: Admin API port-forward did not start"
        return 1
    fi
    local pf_pid=$PORT_FORWARD_PID pf_port=$PORT_FORWARD_PORT pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$pf_port/health" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Cluster 1: Admin API port-forward did not become ready"
        return 1
    fi

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$pf_port/health" 2>/dev/null || echo "000")
    stop_port_forward "$pf_pid" "$pf_log"

    if [ "$http_code" = "200" ]; then
        test_pass "Cluster 1: Admin API responding (HTTP $http_code)"
        return 0
    fi
    test_fail "Cluster 1: Admin API not responding (HTTP $http_code)"
    return 1
}

test_admin_api_cluster2() {
    log_test "Testing Admin API in Cluster 2..."

    use_cluster "$CLUSTER2_NAME"

    if ! start_port_forward svc/garage 3903 "$NAMESPACE" 30; then
        test_fail "Cluster 2: Admin API port-forward did not start"
        return 1
    fi
    local pf_pid=$PORT_FORWARD_PID pf_port=$PORT_FORWARD_PORT pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$pf_port/health" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Cluster 2: Admin API port-forward did not become ready"
        return 1
    fi

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$pf_port/health" 2>/dev/null || echo "000")
    stop_port_forward "$pf_pid" "$pf_log"

    if [ "$http_code" = "200" ]; then
        test_pass "Cluster 2: Admin API responding (HTTP $http_code)"
        return 0
    fi
    test_fail "Cluster 2: Admin API not responding (HTTP $http_code)"
    return 1
}

test_zone_distribution() {
    log_test "Testing zone assignment in each cluster..."

    local c1_zone=""
    local c2_zone=""

    # Check cluster 1 zone
    use_cluster "$CLUSTER1_NAME"
    c1_zone=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.spec.zone}' 2>/dev/null)

    # Check cluster 2 zone
    use_cluster "$CLUSTER2_NAME"
    c2_zone=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.spec.zone}' 2>/dev/null)

    if [ "$c1_zone" = "zone-a" ] && [ "$c2_zone" = "zone-b" ]; then
        test_pass "Zones correctly assigned (cluster1: $c1_zone, cluster2: $c2_zone)"
        return 0
    fi
    test_fail "Zone assignment issue (cluster1: $c1_zone, cluster2: $c2_zone)"
    return 1
}

# ============================================================================
# Gateway Cluster Tests
# ============================================================================
# These tests verify the gateway cluster functionality where a GarageCluster
# with gateway: true connects to an existing storage cluster without storing data.

create_gateway_cluster() {
    local cluster_name=$1
    local gateway_name=$2
    local storage_cluster_name=$3
    local rpc_secret=$4
    local admin_token=$5

    log_info "Creating Gateway GarageCluster '$gateway_name' in '$cluster_name' (connects to: $storage_cluster_name)"

    use_cluster "$cluster_name"

    # Create GarageCluster in gateway mode
    cat <<EOF | kubectl_apply_with_retries
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: $gateway_name
  namespace: $NAMESPACE
spec:
  image: "dxflrs/garage:v2.2.0@sha256:45a61ce3f7c9c24fc23d9ed2b09b27ed560ab87b34605d175d5c588f539c24e4"
  gateway:
    replicas: 1
  replication:
    factor: 2
  connectTo:
    clusterRef:
      name: $storage_cluster_name
      namespace: $NAMESPACE
  network:
    rpcBindPort: 3901
    rpcSecretRef:
      name: garage-rpc-secret
      key: rpc-secret
  admin:
    bindPort: 3903
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
  s3Api:
    bindPort: 3900
    region: garage
EOF
}

test_gateway_cluster_creation() {
    log_test "Testing gateway cluster creation..."

    use_cluster "$CLUSTER1_NAME"

    # Create gateway cluster that connects to the main storage cluster
    create_gateway_cluster "$CLUSTER1_NAME" "garage-gateway" "garage" "$RPC_SECRET" "$SHARED_ADMIN_TOKEN"

    # Wait for gateway to be ready
    if check_resource_phase "garagecluster" "garage-gateway" "Running" 120; then
        local ready
        ready=$(kubectl get garagecluster garage-gateway -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}')
        if [ "$ready" = "1" ]; then
            test_pass "Gateway cluster created with $ready ready replica"
            return 0
        fi
    fi
    test_fail "Gateway cluster creation failed"
    kubectl get garagecluster garage-gateway -n "$NAMESPACE" -o yaml 2>/dev/null | tail -30
    return 1
}

test_gateway_in_layout() {
    log_test "Testing gateway node IS in storage cluster layout with capacity=nil (matches upstream garage layout assign --gateway)..."

    use_cluster "$CLUSTER1_NAME"

    # Get the admin token
    local admin_token
    admin_token=$(kubectl get secret garage-admin-token -n "$NAMESPACE" -o jsonpath='{.data.admin-token}' 2>/dev/null | base64 -d)
    if [ -z "$admin_token" ]; then
        test_fail "Could not get admin token"
        return 1
    fi

    # Wait for service to be ready
    if ! kubectl get svc garage -n "$NAMESPACE" &>/dev/null; then
        test_fail "Storage cluster service 'garage' not found"
        return 1
    fi

    # Port forward to storage cluster with retry
    local layout_info=""
    local status_info=""
    local pf_port pf_pid pf_log

    for attempt in 1 2 3; do
        if start_port_forward svc/garage 3903 "$NAMESPACE" 30; then
            pf_pid=$PORT_FORWARD_PID
            pf_port=$PORT_FORWARD_PORT
            pf_log=$PORT_FORWARD_LOG
        else
            pf_pid=""
            pf_port=""
            pf_log=""
        fi

        if [ -n "$pf_pid" ] && wait_for_port_forward "$pf_pid" "http://127.0.0.1:${pf_port}/health" 30 "$pf_log"; then
            # Get layout AND cluster status from storage cluster
            layout_info=$(curl -s --connect-timeout 10 -H "Authorization: Bearer ${admin_token}" \
                "http://127.0.0.1:${pf_port}/v2/GetClusterLayout" 2>/dev/null)
            status_info=$(curl -s --connect-timeout 10 -H "Authorization: Bearer ${admin_token}" \
                "http://127.0.0.1:${pf_port}/v2/GetClusterStatus" 2>/dev/null)
        else
            layout_info=""
            status_info=""
        fi
        if [ -n "$pf_pid" ]; then
            stop_port_forward "$pf_pid" "$pf_log"
        fi

        if [ -n "$layout_info" ] && echo "$layout_info" | jq -e '.roles' &>/dev/null; then
            break
        fi
        log_info "  Retry $attempt: waiting for layout API (response: ${layout_info:0:100})..."
        sleep 3
    done

    # Gateway pods ARE in the layout with capacity=null. Required so FullReplication
    # writes (key_table, bucket_table, …) target their local DB — see
    # src/api/common/signature/payload.rs:413 in upstream Garage (get_local).
    local gateway_in_layout
    gateway_in_layout=$(echo "$layout_info" | jq '[.roles[] | select(.capacity == null)] | length' 2>/dev/null || echo "0")
    local storage_in_layout
    storage_in_layout=$(echo "$layout_info" | jq '[.roles[] | select(.capacity != null)] | length' 2>/dev/null || echo "0")

    log_info "  Gateway nodes in layout (expect >=1): $gateway_in_layout"
    log_info "  Storage nodes in layout: $storage_in_layout"

    if [ "$gateway_in_layout" -ge 1 ] && [ "$storage_in_layout" -ge 1 ]; then
        test_pass "Gateway is in layout with capacity=nil (layout: $storage_in_layout storage / $gateway_in_layout gateway)"
        return 0
    fi

    test_fail "Gateway layout state unexpected (gw-in-layout: $gateway_in_layout, storage-in-layout: $storage_in_layout)"
    echo "Layout response: $layout_info" | head -20
    echo "$layout_info" | jq '.roles' 2>/dev/null || true
    return 1
}

test_gateway_s3_operations() {
    log_test "Testing S3 operations through gateway cluster..."

    use_cluster "$CLUSTER1_NAME"

    # Check if gateway service exists
    if ! kubectl get svc garage-gateway -n "$NAMESPACE" &>/dev/null; then
        test_fail "Gateway service 'garage-gateway' not found"
        kubectl get svc -n "$NAMESPACE"
        return 1
    fi

    # Get credentials from test-key
    local access_key
    access_key=$(kubectl get secret test-credentials -n "$NAMESPACE" -o jsonpath='{.data.access-key-id}' 2>/dev/null | base64 -d)
    local secret_key
    secret_key=$(kubectl get secret test-credentials -n "$NAMESPACE" -o jsonpath='{.data.secret-access-key}' 2>/dev/null | base64 -d)

    if [ -z "$access_key" ] || [ -z "$secret_key" ]; then
        test_fail "Gateway S3: Could not get credentials from secret"
        return 1
    fi

    log_info "  Testing S3 through gateway (access key: $access_key)"

    # Port forward to gateway cluster's S3 API with retry
    local http_code="000"
    local pf_port pf_pid pf_log

    for attempt in 1 2 3; do
        if start_port_forward svc/garage-gateway 3900 "$NAMESPACE" 30; then
            pf_pid=$PORT_FORWARD_PID
            pf_port=$PORT_FORWARD_PORT
            pf_log=$PORT_FORWARD_LOG
        else
            pf_pid=""
            pf_port=""
            pf_log=""
        fi

        if [ -n "$pf_pid" ] && wait_for_port_forward "$pf_pid" "http://127.0.0.1:${pf_port}/" 30 "$pf_log"; then
            # Test connectivity
            http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 "http://127.0.0.1:${pf_port}/" 2>/dev/null || echo "000")
        else
            http_code="000"
        fi

        if [ -n "$pf_pid" ]; then
            stop_port_forward "$pf_pid" "$pf_log"
        fi

        if [ "$http_code" != "000" ]; then
            break
        fi
        log_info "  Retry $attempt: waiting for gateway S3 API..."
        sleep 3
    done

    if [ "$http_code" = "403" ] || [ "$http_code" = "200" ]; then
        # 403 is expected without proper auth, 200 if bucket listing works
        # This just verifies the gateway is accepting S3 connections
        test_pass "Gateway S3 API responding (HTTP $http_code)"
        return 0
    fi

    test_fail "Gateway S3 API not responding (HTTP $http_code)"
    kubectl get pods -n "$NAMESPACE" -l "garage.rajsingh.info/cluster=garage-gateway"
    kubectl logs -n "$NAMESPACE" -l "garage.rajsingh.info/cluster=garage-gateway" --tail=20 2>/dev/null || true
    return 1
}

test_gateway_does_not_remove_storage_nodes() {
    log_test "Testing gateway does not remove storage nodes from layout..."

    use_cluster "$CLUSTER1_NAME"

    # Get the admin token
    local admin_token
    admin_token=$(kubectl get secret garage-admin-token -n "$NAMESPACE" -o jsonpath='{.data.admin-token}' 2>/dev/null | base64 -d)
    if [ -z "$admin_token" ]; then
        test_fail "Could not get admin token"
        return 1
    fi

    # Port forward to storage cluster with retry
    local layout_info=""
    local pf_port pf_pid pf_log

    for attempt in 1 2 3; do
        if start_port_forward svc/garage 3903 "$NAMESPACE" 30; then
            pf_pid=$PORT_FORWARD_PID
            pf_port=$PORT_FORWARD_PORT
            pf_log=$PORT_FORWARD_LOG
        else
            pf_pid=""
            pf_port=""
            pf_log=""
        fi

        if [ -n "$pf_pid" ] && wait_for_port_forward "$pf_pid" "http://127.0.0.1:${pf_port}/health" 30 "$pf_log"; then
            # Get layout
            layout_info=$(curl -s --connect-timeout 10 -H "Authorization: Bearer ${admin_token}" \
                "http://127.0.0.1:${pf_port}/v2/GetClusterLayout" 2>/dev/null)
        else
            layout_info=""
        fi

        if [ -n "$pf_pid" ]; then
            stop_port_forward "$pf_pid" "$pf_log"
        fi

        if [ -n "$layout_info" ] && echo "$layout_info" | jq -e '.roles' &>/dev/null; then
            break
        fi
        log_info "  Retry $attempt: waiting for layout API..."
        sleep 3
    done

    # Count storage nodes (should be >= 2 from the original cluster)
    local storage_nodes
    storage_nodes=$(echo "$layout_info" | jq '[.roles[] | select(.capacity != null)] | length' 2>/dev/null || echo "0")

    # Check for any staged removals (handle empty array)
    local staged_removals
    staged_removals=$(echo "$layout_info" | jq '[.stagedRoleChanges // [] | .[] | select(.remove == true)] | length' 2>/dev/null || echo "0")

    log_info "  Storage nodes in layout: $storage_nodes"
    log_info "  Staged removals: $staged_removals"

    if [ "$storage_nodes" -ge 2 ] && [ "$staged_removals" -eq 0 ]; then
        test_pass "Gateway did not remove storage nodes (storage: $storage_nodes, removals: $staged_removals)"
        return 0
    fi

    if [ "$staged_removals" -gt 0 ]; then
        test_fail "Gateway incorrectly staged node removals (staged: $staged_removals)"
        echo "$layout_info" | jq '.stagedRoleChanges' 2>/dev/null
        return 1
    fi

    test_fail "Unexpected layout state (storage: $storage_nodes, removals: $staged_removals)"
    echo "Layout response: $layout_info" | head -20
    return 1
}

test_gateway_connection_status() {
    log_test "Testing gateway cluster connection status..."

    use_cluster "$CLUSTER1_NAME"

    # Check gateway status
    local gateway_phase
    gateway_phase=$(kubectl get garagecluster garage-gateway -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null)
    local gateway_health
    gateway_health=$(kubectl get garagecluster garage-gateway -n "$NAMESPACE" -o jsonpath='{.status.health.status}' 2>/dev/null)
    local connected_nodes
    connected_nodes=$(kubectl get garagecluster garage-gateway -n "$NAMESPACE" -o jsonpath='{.status.health.connectedNodes}' 2>/dev/null)

    log_info "  Gateway phase: $gateway_phase"
    log_info "  Gateway health: $gateway_health"
    log_info "  Connected nodes: $connected_nodes"

    # Gateway should be Running and see the storage cluster nodes
    if [ "$gateway_phase" = "Running" ] && [ "$connected_nodes" -ge 2 ]; then
        test_pass "Gateway cluster connected to storage cluster (phase: $gateway_phase, nodes: $connected_nodes)"
        return 0
    fi

    test_fail "Gateway cluster not properly connected (phase: $gateway_phase, health: $gateway_health, nodes: $connected_nodes)"
    return 1
}

test_gateway_cleanup() {
    log_test "Testing gateway cluster cleanup..."

    use_cluster "$CLUSTER1_NAME"

    # Delete the gateway cluster and observe the API object disappear rather
    # than assuming a fixed finalizer duration.
    kubectl delete garagecluster garage-gateway -n "$NAMESPACE" \
        --ignore-not-found=true --wait=false --request-timeout=15s 2>/dev/null || true

    if wait_for_resource_deleted garagecluster garage-gateway 180; then
        test_pass "Gateway cluster cleaned up successfully"
        return 0
    fi

    test_fail "Gateway cluster not cleaned up"
    return 1
}

test_gateway_cleanup_layout() {
    log_test "Testing gateway node removed from storage cluster layout after cleanup..."

    use_cluster "$CLUSTER1_NAME"

    # Get the admin token
    local admin_token
    admin_token=$(kubectl get secret garage-admin-token -n "$NAMESPACE" -o jsonpath='{.data.admin-token}' 2>/dev/null | base64 -d)
    if [ -z "$admin_token" ]; then
        test_fail "Could not get admin token"
        return 1
    fi

    # Port forward to storage cluster admin API
    local pf_port pf_pid pf_log
    if ! start_port_forward svc/garage 3903 "$NAMESPACE" 30; then
        test_fail "Gateway cleanup: Admin API port-forward did not start"
        return 1
    fi
    pf_pid=$PORT_FORWARD_PID
    pf_port=$PORT_FORWARD_PORT
    pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:${pf_port}/health" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Gateway cleanup: Admin API port-forward did not become ready"
        return 1
    fi

    # Get layout with retries
    local layout_info=""
    for attempt in 1 2 3; do
        layout_info=$(curl -s --connect-timeout 10 -H "Authorization: Bearer ${admin_token}" \
            "http://127.0.0.1:${pf_port}/v2/GetClusterLayout" 2>/dev/null)
        if [ -n "$layout_info" ] && echo "$layout_info" | jq -e '.roles' &>/dev/null; then
            break
        fi
        log_info "  Retry $attempt: waiting for layout API..."
        sleep 3
    done

    stop_port_forward "$pf_pid" "$pf_log"

    if [ -z "$layout_info" ]; then
        test_fail "Could not get layout info"
        return 1
    fi

    # Count gateway nodes (nil capacity) in layout
    local gateway_nodes
    gateway_nodes=$(echo "$layout_info" | jq '[.roles[] | select(.capacity == null)] | length' 2>/dev/null || echo "0")
    local storage_nodes
    storage_nodes=$(echo "$layout_info" | jq '[.roles[] | select(.capacity != null)] | length' 2>/dev/null || echo "0")

    # Check for staged removals
    local staged_removals
    staged_removals=$(echo "$layout_info" | jq '[.stagedRoleChanges // [] | .[] | select(.remove == true)] | length' 2>/dev/null || echo "0")

    log_info "  Gateway nodes (nil capacity): $gateway_nodes"
    log_info "  Storage nodes (with capacity): $storage_nodes"
    log_info "  Staged removals: $staged_removals"

    # After gateway deletion, there should be no gateway nodes in the layout
    if [ "$gateway_nodes" -eq 0 ] && [ "$storage_nodes" -ge 1 ]; then
        test_pass "Gateway node removed from storage cluster layout (gateways: $gateway_nodes, storage: $storage_nodes)"
        return 0
    fi

    # A staged removal is not proof that cleanup completed.
    if [ "$gateway_nodes" -ge 1 ] && [ "$staged_removals" -ge 1 ]; then
        test_fail "Gateway node removal is still pending layout application (gateways: $gateway_nodes, staged removals: $staged_removals)"
        return 1
    fi

    test_fail "Gateway node not removed from layout (gateways: $gateway_nodes, staged removals: $staged_removals)"
    echo "Layout response: $layout_info" | head -30
    return 1
}

# Test that self-connections are skipped when remote zone matches local zone
# This is important for templated deployments where all clusters have the same
# remoteClusters list (e.g., ottawa/robbinsdale/stpetersburg each listing all 3)
test_self_connection_skip() {
    log_test "Testing self-connection skip (remote zone == local zone)..."

    use_cluster "$CLUSTER1_NAME"

    # Get current zone
    local local_zone
    local_zone=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.spec.zone}')
    log_info "  Local zone: $local_zone"

    # Get a pod IP to use as fake "self" endpoint
    local pod_ip
    pod_ip=$(pod_ip_for_selector "$NAMESPACE" "garage.rajsingh.info/cluster=garage" || true)
    if [ -z "$pod_ip" ]; then
        test_fail "Self-connection test could not find an active Garage Pod IP"
        return 1
    fi

    # Patch to add self as a remote cluster (same zone)
    log_info "  Adding self to remoteClusters with matching zone..."
    kubectl patch garagecluster garage -n "$NAMESPACE" --type=json -p "[
      {\"op\": \"add\", \"path\": \"/spec/remoteClusters/-\", \"value\": {
        \"name\": \"self-test\",
        \"zone\": \"$local_zone\",
        \"connection\": {
          \"adminApiEndpoint\": \"http://${pod_ip}:3903\",
          \"adminTokenSecretRef\": {
            \"name\": \"garage-admin-token\",
            \"key\": \"admin-token\"
          }
        }
      }}
    ]"

    # Trigger reconciliation
    kubectl annotate garagecluster garage -n "$NAMESPACE" --overwrite \
        "test.garage.rajsingh.info/trigger=$(date +%s)"

    # Check operator logs for self-connection skip message
    # Use head -1 and tr to ensure we get a clean integer (kubectl may return multiple lines)
    local skip_log
    local skip_deadline=$((SECONDS + 60))
    skip_log=0
    while [ "$SECONDS" -lt "$skip_deadline" ]; do
        skip_log=$(kubectl logs deployment/garage-operator -n "$NAMESPACE" --tail=100 2>/dev/null | \
            grep -c "Skipping self-connection" 2>/dev/null | head -1 | tr -d '[:space:]')
        skip_log=${skip_log:-0}
        [ "$skip_log" -gt 0 ] 2>/dev/null && break
        sleep 2
    done
    skip_log=${skip_log:-0}

    # Remove the self-test entry from remoteClusters
    log_info "  Cleaning up self-test entry..."
    local self_index
    # Compute the JSON-Patch position from the live object so a pre-existing
    # remote list can be in any order. jq's to_entries preserves actual indexes.
    self_index=$(kubectl get garagecluster garage -n "$NAMESPACE" -o json 2>/dev/null |
        jq -r '[.spec.remoteClusters // [] | to_entries[] | select(.value.name == "self-test") | .key] | if length == 1 then first else empty end' 2>/dev/null || true)
    if [[ ! "$self_index" =~ ^[0-9]+$ ]] ||
        ! kubectl patch garagecluster garage -n "$NAMESPACE" --type=json -p "[
      {\"op\": \"remove\", \"path\": \"/spec/remoteClusters/$self_index\"}
    ]" >/dev/null 2>&1; then
        test_fail "Self-connection test peer could not be removed"
        return 1
    fi

    if [ "$skip_log" -gt 0 ] 2>/dev/null; then
        test_pass "Self-connection correctly skipped when remote zone matches local zone"
        return 0
    fi

    test_fail "Self-connection skip was not observed in operator logs"
    return 1
}

# ============================================================================
# Manual Mode with GarageNodes Multi-Cluster Test
# ============================================================================
# Tests Manual mode where GarageCluster doesn't create StatefulSets,
# and instead 2 GarageNodes per cluster create their own StatefulSets.

test_manual_mode_multicluster_setup() {
    log_test "Setting up Manual mode multi-cluster test..."

    if ! teardown_whole_federated_store; then
        test_fail "Previous federated store did not finish serialized whole-store teardown"
        return 1
    fi

    test_pass "Manual mode multi-cluster test setup complete"
    return 0
}

create_manual_mode_cluster() {
    local cluster_name=$1
    local garage_name=$2
    local zone=$3
    local rpc_secret=$4
    local admin_token=$5

    log_info "Creating Manual mode GarageCluster '$garage_name' in '$cluster_name' (zone: $zone)"

    use_cluster "$cluster_name"

    # Create RPC secret
    kubectl create secret generic garage-rpc-secret -n "$NAMESPACE" \
        --from-literal=rpc-secret="$rpc_secret" 2>/dev/null || true

    # Create admin token
    kubectl create secret generic garage-admin-token -n "$NAMESPACE" \
        --from-literal=admin-token="$admin_token" 2>/dev/null || true

    # Create GarageCluster with layoutPolicy: Manual (no StatefulSet)
    cat <<EOF | kubectl_apply_with_retries
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: $garage_name
  namespace: $NAMESPACE
spec:
  layoutPolicy: Manual
  storage:
    metadata:
      size: 100Mi
    data:
      size: 1Gi
  zone: $zone
  image: "dxflrs/garage:v2.2.0@sha256:45a61ce3f7c9c24fc23d9ed2b09b27ed560ab87b34605d175d5c588f539c24e4"
  replication:
    factor: 2
    consistencyMode: consistent
  network:
    rpcBindPort: 3901
    rpcSecretRef:
      name: garage-rpc-secret
      key: rpc-secret
  admin:
    bindPort: 3903
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
  s3Api:
    bindPort: 3900
    region: garage
EOF
}

create_garagenode() {
    local cluster_name=$1
    local node_name=$2
    local garage_name=$3
    local zone=$4
    local capacity=$5

    log_info "Creating GarageNode '$node_name' in '$cluster_name'"

    use_cluster "$cluster_name"

    cat <<EOF | kubectl_apply_with_retries
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: $node_name
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: $garage_name
  zone: $zone
  capacity: $capacity
  storage:
    metadata:
      size: 100Mi
    data:
      size: 1Gi
EOF
}

test_manual_mode_cluster_creation_multicluster() {
    log_test "Testing Manual mode GarageCluster creation in both clusters..."

    # Create Manual mode clusters
    create_manual_mode_cluster "$CLUSTER1_NAME" "garage" "zone-a" "$RPC_SECRET" "$SHARED_ADMIN_TOKEN"
    create_manual_mode_cluster "$CLUSTER2_NAME" "garage" "zone-b" "$RPC_SECRET" "$SHARED_ADMIN_TOKEN"

    # Verify no StatefulSets created (Manual mode)
    use_cluster "$CLUSTER1_NAME"
    if ! wait_for_resource_deleted statefulset garage 60; then
        test_fail "Cluster 1: StatefulSet should NOT exist for Manual mode cluster"
        return 1
    fi

    use_cluster "$CLUSTER2_NAME"
    if ! wait_for_resource_deleted statefulset garage 60; then
        test_fail "Cluster 2: StatefulSet should NOT exist for Manual mode cluster"
        return 1
    fi

    test_pass "Manual mode clusters created without StatefulSets"
    return 0
}

test_manual_mode_garagenodes_creation() {
    log_test "Testing GarageNode creation (2 nodes per cluster, 4 total)..."

    # Create 2 GarageNodes in cluster 1
    create_garagenode "$CLUSTER1_NAME" "node-1a" "garage" "zone-a" "1Gi"
    create_garagenode "$CLUSTER1_NAME" "node-2a" "garage" "zone-a" "1Gi"

    # Create 2 GarageNodes in cluster 2
    create_garagenode "$CLUSTER2_NAME" "node-1b" "garage" "zone-b" "1Gi"
    create_garagenode "$CLUSTER2_NAME" "node-2b" "garage" "zone-b" "1Gi"

    # Verify StatefulSets are created for each node
    local c1_sts_count=0
    local c2_sts_count=0
    local sts_deadline=$((SECONDS + 120))
    while [ "$SECONDS" -lt "$sts_deadline" ]; do
        use_cluster "$CLUSTER1_NAME"
        c1_sts_count=$(kubectl get statefulset -n "$NAMESPACE" -l "garage.rajsingh.info/node" \
            --no-headers 2>/dev/null | wc -l | tr -d ' ')
        use_cluster "$CLUSTER2_NAME"
        c2_sts_count=$(kubectl get statefulset -n "$NAMESPACE" -l "garage.rajsingh.info/node" \
            --no-headers 2>/dev/null | wc -l | tr -d ' ')
        if [ "$c1_sts_count" -ge 2 ] && [ "$c2_sts_count" -ge 2 ]; then
            break
        fi
        sleep 2
    done

    if [ "$c1_sts_count" -ge 2 ] && [ "$c2_sts_count" -ge 2 ]; then
        test_pass "GarageNodes created StatefulSets (c1: $c1_sts_count, c2: $c2_sts_count)"
        return 0
    fi

    test_fail "Not all GarageNode StatefulSets created (c1: $c1_sts_count, c2: $c2_sts_count)"
    return 1
}

test_manual_mode_pods_running() {
    log_test "Testing all GarageNode pods are running..."

    # Wait for pods in cluster 1
    use_cluster "$CLUSTER1_NAME"
    if ! wait_for_pods_ready "garage.rajsingh.info/node" 2 180; then
        test_fail "Cluster 1: GarageNode pods not ready"
        return 1
    fi

    # Wait for pods in cluster 2
    use_cluster "$CLUSTER2_NAME"
    if ! wait_for_pods_ready "garage.rajsingh.info/node" 2 180; then
        test_fail "Cluster 2: GarageNode pods not ready"
        return 1
    fi

    test_pass "All GarageNode pods are running (4 total)"
    return 0
}

test_manual_mode_nodes_in_layout() {
    log_test "Testing all GarageNodes registered in layout..."

    local timeout=120
    local end_time=$((SECONDS + timeout))

    while [ $SECONDS -lt $end_time ]; do
        # Count nodes in layout in cluster 1
        use_cluster "$CLUSTER1_NAME"
        local c1_n1
        c1_n1=$(kubectl get garagenode node-1a -n "$NAMESPACE" -o jsonpath='{.status.inLayout}' 2>/dev/null || echo "false")
        local c1_n2
        c1_n2=$(kubectl get garagenode node-2a -n "$NAMESPACE" -o jsonpath='{.status.inLayout}' 2>/dev/null || echo "false")

        # Count nodes in layout in cluster 2
        use_cluster "$CLUSTER2_NAME"
        local c2_n1
        c2_n1=$(kubectl get garagenode node-1b -n "$NAMESPACE" -o jsonpath='{.status.inLayout}' 2>/dev/null || echo "false")
        local c2_n2
        c2_n2=$(kubectl get garagenode node-2b -n "$NAMESPACE" -o jsonpath='{.status.inLayout}' 2>/dev/null || echo "false")

        if [ "$c1_n1" = "true" ] && [ "$c1_n2" = "true" ] && [ "$c2_n1" = "true" ] && [ "$c2_n2" = "true" ]; then
            test_pass "All 4 GarageNodes registered in layout"
            return 0
        fi
        sleep 10
    done

    test_fail "Not all nodes in layout (c1: $c1_n1/$c1_n2, c2: $c2_n1/$c2_n2)"
    return 1
}

test_manual_mode_cluster_health_multicluster() {
    log_test "Testing Manual mode cluster health (2 nodes per cluster)..."

    local c1_connected=0 c2_connected=0
    use_cluster "$CLUSTER1_NAME"
    if ! wait_for_cluster_health_and_nodes garage healthy 2 120; then
        c1_connected=$(get_connected_nodes "garage")
        test_fail "Cluster 1 not healthy (connected: ${c1_connected:-unknown})"
        return 1
    fi
    c1_connected=$(get_connected_nodes "garage")

    use_cluster "$CLUSTER2_NAME"
    if ! wait_for_cluster_health_and_nodes garage healthy 2 120; then
        c2_connected=$(get_connected_nodes "garage")
        test_fail "Cluster 2 not healthy (connected: ${c2_connected:-unknown})"
        return 1
    fi
    c2_connected=$(get_connected_nodes "garage")

    test_pass "Both clusters have healthy nodes (c1: $c1_connected, c2: $c2_connected)"
    return 0
}

test_manual_mode_federation_multicluster() {
    log_test "Testing Manual mode cross-cluster federation..."

    # Configure remoteClusters for federation
    use_cluster "$CLUSTER1_NAME"
    local c1_pod_ip
    c1_pod_ip=$(pod_ip_for_selector "$NAMESPACE" "garage.rajsingh.info/node" || true)

    use_cluster "$CLUSTER2_NAME"
    local c2_pod_ip
    c2_pod_ip=$(pod_ip_for_selector "$NAMESPACE" "garage.rajsingh.info/node" || true)

    log_info "  Cluster 1 pod IP: $c1_pod_ip"
    log_info "  Cluster 2 pod IP: $c2_pod_ip"

    # Patch clusters with remoteClusters
    patch_garage_with_remote_clusters "$CLUSTER1_NAME" "garage" "cluster2" "zone-b" "http://${c2_pod_ip}:3903"
    patch_garage_with_remote_clusters "$CLUSTER2_NAME" "garage" "cluster1" "zone-a" "http://${c1_pod_ip}:3903"

    log_info "  Waiting for bidirectional federation to establish..."
    local c1_connected=0 c2_connected=0
    if wait_for_federated_peers 180 3; then
        c1_connected=$FEDERATED_CLUSTER1_CONNECTED
        c2_connected=$FEDERATED_CLUSTER2_CONNECTED
        test_pass "Bidirectional cross-cluster federation working (c1 sees $c1_connected nodes, c2 sees $c2_connected nodes)"
        return 0
    fi

    c1_connected=$FEDERATED_CLUSTER1_CONNECTED
    c2_connected=$FEDERATED_CLUSTER2_CONNECTED
    test_fail "Bidirectional federation not established (c1: $c1_connected, c2: $c2_connected)"
    return 1
}

test_manual_mode_bucket_operations_multicluster() {
    log_test "Testing bucket operations on Manual mode federated cluster..."

    use_cluster "$CLUSTER1_NAME"

    # Create a bucket
    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: manual-fed-bucket
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  globalAlias: manual-fed-bucket
EOF

    if check_resource_phase "garagebucket" "manual-fed-bucket" "Ready" 60; then
        test_pass "Bucket created on Manual mode federated cluster"
        kubectl delete garagebucket manual-fed-bucket -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        return 0
    fi

    test_fail "Bucket creation failed on Manual mode cluster"
    kubectl delete garagebucket manual-fed-bucket -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true
    return 1
}

test_manual_mode_cleanup_multicluster() {
    log_test "Testing Manual mode multi-cluster cleanup..."

    if ! teardown_whole_federated_store; then
        test_fail "Manual federated store did not finish serialized whole-store teardown"
        return 1
    fi

    test_pass "Manual mode clusters, nodes, and StatefulSets cleaned up"
    return 0
}

# ============================================================================
# Single-Replica Federation Test (Bug Regression Test)
# ============================================================================
# This test catches the multi-cluster deadlock bug where:
# - Each cluster has replicas < replicationFactor
# - Without the fix, clusters wait forever for more nodes before applying layout
# - With the fix, clusters with remoteClusters configured apply layout immediately

test_single_replica_federation() {
    log_info "=== Single-Replica Federation Test (Regression) ==="
    log_info "Testing: replicas=1 per cluster, replicationFactor=2 (relies on federation)"

    # Delete existing GarageClusters
    log_info "Cleaning up existing GarageClusters..."
    if ! teardown_whole_federated_store; then
        test_fail "Single-replica setup: previous federated store did not finish serialized teardown"
        return 1
    fi

    log_info "Creating single-replica GarageClusters with replicationFactor=2..."

    # Create both one-node clusters before configuring federation. Once their
    # pod IPs are known, remoteClusters is added while each side still has fewer
    # nodes than replicationFactor, preserving the regression condition.
    use_cluster "$CLUSTER1_NAME"
    create_garage_cluster "$CLUSTER1_NAME" "garage" "zone-a" "$RPC_SECRET" "" 1 2 "" "$SHARED_ADMIN_TOKEN"

    use_cluster "$CLUSTER2_NAME"
    create_garage_cluster "$CLUSTER2_NAME" "garage" "zone-b" "$RPC_SECRET" "" 1 2 "" "$SHARED_ADMIN_TOKEN"

    # Wait for pods to be ready
    log_info "Waiting for single-replica pods..."
    use_cluster "$CLUSTER1_NAME"
    if ! wait_for_pods_ready "garage.rajsingh.info/cluster=garage" 1 "$TIMEOUT"; then
        test_fail "Single-replica test: Cluster 1 pod failed to start"
        return 1
    fi

    use_cluster "$CLUSTER2_NAME"
    if ! wait_for_pods_ready "garage.rajsingh.info/cluster=garage" 1 "$TIMEOUT"; then
        test_fail "Single-replica test: Cluster 2 pod failed to start"
        return 1
    fi

    # Resolve each remote endpoint from the opposite Kubernetes context. Using
    # pod IPs matches the federation mechanism exercised by the main scenario
    # and avoids cluster-local Service DNS resolving back to the local Garage.
    local c1_pod_ip
    local c2_pod_ip
    c1_pod_ip=$(pod_ip_for_selector "$NAMESPACE" \
        "garage.rajsingh.info/cluster=garage" "kind-$CLUSTER1_NAME" || true)
    c2_pod_ip=$(pod_ip_for_selector "$NAMESPACE" \
        "garage.rajsingh.info/cluster=garage" "kind-$CLUSTER2_NAME" || true)

    if [[ ! "$c1_pod_ip" =~ ^10\.244\. ]] || [[ ! "$c2_pod_ip" =~ ^10\.245\. ]] ||
        [ "$c1_pod_ip" = "$c2_pod_ip" ]; then
        test_fail "Single-replica test: Garage pod IPs do not identify opposite kind pod networks (c1: $c1_pod_ip, c2: $c2_pod_ip)"
        return 1
    fi

    local c1_remote_endpoint="http://${c2_pod_ip}:3903"
    local c2_remote_endpoint="http://${c1_pod_ip}:3903"
    local reconciliation_since
    reconciliation_since=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    patch_garage_with_remote_clusters "$CLUSTER1_NAME" "garage" "cluster2" "zone-b" "$c1_remote_endpoint"
    patch_garage_with_remote_clusters "$CLUSTER2_NAME" "garage" "cluster1" "zone-a" "$c2_remote_endpoint"

    local c1_configured_endpoint
    local c2_configured_endpoint
    c1_configured_endpoint=$(kubectl --context "kind-$CLUSTER1_NAME" get garagecluster garage \
        -n "$NAMESPACE" -o json 2>/dev/null |
        jq -r '[.spec.remoteClusters[]? | select(.name == "cluster2") | .connection.adminApiEndpoint] | if length == 1 then first else empty end')
    c2_configured_endpoint=$(kubectl --context "kind-$CLUSTER2_NAME" get garagecluster garage \
        -n "$NAMESPACE" -o json 2>/dev/null |
        jq -r '[.spec.remoteClusters[]? | select(.name == "cluster1") | .connection.adminApiEndpoint] | if length == 1 then first else empty end')

    if [ "$c1_configured_endpoint" != "$c1_remote_endpoint" ] ||
        [ "$c2_configured_endpoint" != "$c2_remote_endpoint" ] ||
        [ "$c1_configured_endpoint" = "http://${c1_pod_ip}:3903" ] ||
        [ "$c2_configured_endpoint" = "http://${c2_pod_ip}:3903" ]; then
        test_fail "Single-replica test: remote endpoints do not target the opposite clusters (c1 target: $c1_configured_endpoint, c2 target: $c2_configured_endpoint)"
        return 1
    fi
    log_info "  Verified Cluster 1 targets Cluster 2 pod $c2_pod_ip"
    log_info "  Verified Cluster 2 targets Cluster 1 pod $c1_pod_ip"

    # The key test: Verify an operator ATTEMPTS to apply the shared Garage layout
    # despite each Kubernetes cluster having only 1 node < replicationFactor.
    # Either site may win the apply race because both operators mutate the same
    # Garage layout. The losing site can briefly hold stale Kubernetes status
    # while its GarageNode reconciler owns that process's layout lock, so wait
    # for evidence of progress from either site instead of requiring both
    # controller logs/status objects to independently report the shared apply.
    log_test "Testing operator attempts layout apply with single replica (replicationFactor=2, remoteClusters configured)..."

    # With the fix, one operator logs a federated apply attempt/success or one
    # status observes the resulting committed layout. Without the fix, both
    # operators remain at "Waiting for more nodes" indefinitely.
    local c1_logs=""
    local c2_logs=""
    local c1_layout_version=""
    local c2_layout_version=""
    local layout_progress=""
    local layout_deadline=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$layout_deadline" ]; do
        c1_logs=$(kubectl --context "kind-$CLUSTER1_NAME" logs \
            -l app.kubernetes.io/name=garage-operator -n "$NAMESPACE" \
            --since-time="$reconciliation_since" --tail=-1 2>/dev/null || true)
        c2_logs=$(kubectl --context "kind-$CLUSTER2_NAME" logs \
            -l app.kubernetes.io/name=garage-operator -n "$NAMESPACE" \
            --since-time="$reconciliation_since" --tail=-1 2>/dev/null || true)
        c1_layout_version=$(kubectl --context "kind-$CLUSTER1_NAME" get garagecluster garage \
            -n "$NAMESPACE" -o jsonpath='{.status.layoutVersion}' 2>/dev/null || true)
        c2_layout_version=$(kubectl --context "kind-$CLUSTER2_NAME" get garagecluster garage \
            -n "$NAMESPACE" -o jsonpath='{.status.layoutVersion}' 2>/dev/null || true)

        if grep -q "Applied federated layout" <<<"$c1_logs"; then
            layout_progress="Cluster 1 committed the shared federated layout"
            break
        fi
        if grep -q "Applied federated layout" <<<"$c2_logs"; then
            layout_progress="Cluster 2 committed the shared federated layout"
            break
        fi
        if grep -q "Applying layout despite insufficient nodes" <<<"$c1_logs"; then
            layout_progress="Cluster 1 operator attempted the shared layout apply"
            break
        fi
        if grep -q "Applying layout despite insufficient nodes" <<<"$c2_logs"; then
            layout_progress="Cluster 2 operator attempted the shared layout apply"
            break
        fi
        if [[ "$c1_layout_version" =~ ^[0-9]+$ ]] && [ "$c1_layout_version" -gt 0 ]; then
            layout_progress="Cluster 1 observed committed shared layout version $c1_layout_version"
            break
        fi
        if [[ "$c2_layout_version" =~ ^[0-9]+$ ]] && [ "$c2_layout_version" -gt 0 ]; then
            layout_progress="Cluster 2 observed committed shared layout version $c2_layout_version"
            break
        fi
        sleep 3
    done

    if [ -n "$layout_progress" ]; then
        test_pass "Single-replica test: $layout_progress"
    elif grep -q "Waiting for more nodes before applying layout" <<<"$c1_logs" &&
        grep -q "Waiting for more nodes before applying layout" <<<"$c2_logs"; then
        test_fail "Single-replica test: DEADLOCK BUG - both operators waited for nodes instead of attempting the shared layout"
        log_error "The multi-cluster federation fix is not working!"
        return 1
    else
        test_fail "Single-replica test: no shared layout attempt or commit observed (c1 version: ${c1_layout_version:-missing}, c2 version: ${c2_layout_version:-missing})"
        return 1
    fi

    # Require both clusters to reach Running and see the opposite Garage peer.
    local c1_phase=""
    local c2_phase=""
    local c1_connected=0
    local c2_connected=0
    # Status publication may follow the successful shared apply on the
    # controller's periodic requeue. Use the script-wide convergence timeout
    # so a requeue landing just beyond one minute cannot create a false failure.
    local phase_deadline=$((SECONDS + TIMEOUT))
    while [ "$SECONDS" -lt "$phase_deadline" ]; do
        c1_phase=$(kubectl --context "kind-$CLUSTER1_NAME" get garagecluster garage \
            -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null)
        c2_phase=$(kubectl --context "kind-$CLUSTER2_NAME" get garagecluster garage \
            -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null)
        c1_connected=$(kubectl --context "kind-$CLUSTER1_NAME" get garagecluster garage \
            -n "$NAMESPACE" -o jsonpath='{.status.health.connectedNodes}' 2>/dev/null || echo "0")
        c2_connected=$(kubectl --context "kind-$CLUSTER2_NAME" get garagecluster garage \
            -n "$NAMESPACE" -o jsonpath='{.status.health.connectedNodes}' 2>/dev/null || echo "0")
        c1_connected=${c1_connected:-0}
        c2_connected=${c2_connected:-0}

        if [ "$c1_phase" = "Running" ] && [ "$c2_phase" = "Running" ] &&
            [[ "$c1_connected" =~ ^[0-9]+$ ]] &&
            [[ "$c2_connected" =~ ^[0-9]+$ ]] &&
            [ "$c1_connected" -gt 1 ] && [ "$c2_connected" -gt 1 ]; then
            break
        fi
        sleep 5
    done

    if [ "$c1_phase" = "Running" ] && [ "$c2_phase" = "Running" ] &&
        [[ "$c1_connected" =~ ^[0-9]+$ ]] &&
        [[ "$c2_connected" =~ ^[0-9]+$ ]] &&
        [ "$c1_connected" -gt 1 ] && [ "$c2_connected" -gt 1 ]; then
        test_pass "Single-replica test: Both clusters reached Running with bidirectional peer convergence (c1: $c1_connected, c2: $c2_connected)"
    else
        test_fail "Single-replica test: Federation did not converge (phases c1: $c1_phase, c2: $c2_phase; peers c1: $c1_connected, c2: $c2_connected)"
        return 1
    fi

    log_info "Single-replica federation test completed successfully"
    return 0
}

# ============================================================================
# Main
# ============================================================================

print_summary() {
    echo ""
    echo "=============================================="
    echo "         MULTI-CLUSTER TEST SUMMARY"
    echo "=============================================="
    echo -e "  ${GREEN}PASSED:${NC}  $TESTS_PASSED"
    echo -e "  ${RED}FAILED:${NC}  $TESTS_FAILED"
    echo -e "  ${YELLOW}SKIPPED:${NC} $TESTS_SKIPPED"
    echo "=============================================="

    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "${RED}Some tests failed!${NC}"
        return 1
    else
        echo -e "${GREEN}All tests passed!${NC}"
        return 0
    fi
}

# The multi-cluster checks mutate a shared federated topology. Continuing after
# one test fails makes later results depend on that partially-mutated topology,
# so stop at the first failed test and let the EXIT trap collect both clusters.
run_e2e_test() {
    local test_name="$1"
    if "$test_name"; then
        return 0
    fi
    log_error "Stopping after $test_name failed; later tests depend on its fixtures"
    print_summary || true
    return 1
}

main() {
    log_info "Starting Multi-Cluster E2E tests for garage-operator"
    log_info "Working directory: $ROOT_DIR"

    cd "$ROOT_DIR"

    # Generate shared RPC secret
    RPC_SECRET=$(generate_rpc_secret)
    log_info "Generated shared RPC secret: ${RPC_SECRET:0:16}..."

    # Generate shared admin token (must be same for cross-cluster authentication)
    SHARED_ADMIN_TOKEN="admin-token-shared-$(date +%s)"
    log_info "Generated shared admin token: ${SHARED_ADMIN_TOKEN:0:20}..."

    # Step 1: Setup Docker network
    log_info "=== Step 1: Setting up Docker network ==="
    setup_docker_network

    # Step 2: Refuse to overwrite clusters not created by this run.
    log_info "=== Step 2: Checking cluster names are available ==="
    for cluster_name in "$CLUSTER1_NAME" "$CLUSTER2_NAME"; do
        if ! kind_cluster_is_absent "$cluster_name"; then
            log_error "Refusing to delete pre-existing kind cluster '$cluster_name'"
            return 1
        fi
    done

    # Step 3: Create kind clusters with unique pod subnets
    log_info "=== Step 3: Creating kind clusters ==="
    if ! create_kind_cluster "$CLUSTER1_NAME" "zone-a" "10.244.0.0/16"; then
        if kind get clusters 2>/dev/null | grep -Fqx -- "$CLUSTER1_NAME"; then
            CLUSTER1_UID=$(kind_cluster_uid "$CLUSTER1_NAME" || true)
            if [ -n "$CLUSTER1_UID" ]; then
                CLUSTER1_CREATED=true
                log_error "kind create failed after creating '$CLUSTER1_NAME'; recorded its ownership for cleanup"
            else
                log_error "kind create failed and left an unproven cluster named '$CLUSTER1_NAME'; refusing deletion"
            fi
        fi
        return 1
    fi
    CLUSTER1_CREATED=true
    CLUSTER1_UID=$(kind_cluster_uid "$CLUSTER1_NAME" || true)
    if [ -z "$CLUSTER1_UID" ]; then
        log_error "Could not record exact ownership of '$CLUSTER1_NAME'"
        return 1
    fi
    if ! create_kind_cluster "$CLUSTER2_NAME" "zone-b" "10.245.0.0/16"; then
        if kind get clusters 2>/dev/null | grep -Fqx -- "$CLUSTER2_NAME"; then
            CLUSTER2_UID=$(kind_cluster_uid "$CLUSTER2_NAME" || true)
            if [ -n "$CLUSTER2_UID" ]; then
                CLUSTER2_CREATED=true
                log_error "kind create failed after creating '$CLUSTER2_NAME'; recorded its ownership for cleanup"
            else
                log_error "kind create failed and left an unproven cluster named '$CLUSTER2_NAME'; refusing deletion"
            fi
        fi
        return 1
    fi
    CLUSTER2_CREATED=true
    CLUSTER2_UID=$(kind_cluster_uid "$CLUSTER2_NAME" || true)
    if [ -z "$CLUSTER2_UID" ]; then
        log_error "Could not record exact ownership of '$CLUSTER2_NAME'"
        return 1
    fi

    # Step 3b: Set up cross-cluster routes
    log_info "=== Step 3b: Setting up cross-cluster networking ==="
    setup_cross_cluster_routes

    # Step 4: Build operator image
    if [ "$SKIP_BUILD" = false ]; then
        log_info "=== Step 4: Building operator image ==="
        docker build -t garage-operator:e2e .
    else
        log_info "=== Step 4: Skipping build (--skip-build) ==="
    fi

    # Step 5: Deploy operator to both clusters
    log_info "=== Step 5: Deploying operator to both clusters ==="
    deploy_operator "$CLUSTER1_NAME"
    deploy_operator "$CLUSTER2_NAME"

    # Step 6: Create GarageClusters
    log_info "=== Step 6: Creating GarageClusters ==="

    # First create both clusters without bootstrap peers (they'll discover each other via Admin API)
    # IMPORTANT: Use same admin token on both clusters for cross-cluster authentication
    use_cluster "$CLUSTER1_NAME"
    create_garage_cluster "$CLUSTER1_NAME" "garage" "zone-a" "$RPC_SECRET" "" 2 2 "" "$SHARED_ADMIN_TOKEN"

    use_cluster "$CLUSTER2_NAME"
    create_garage_cluster "$CLUSTER2_NAME" "garage" "zone-b" "$RPC_SECRET" "" 2 2 "" "$SHARED_ADMIN_TOKEN"

    # Step 7: Wait for pods to be ready
    log_info "=== Step 7: Waiting for Garage pods ==="

    use_cluster "$CLUSTER1_NAME"
    wait_for_pods_ready "garage.rajsingh.info/cluster=garage" 2 "$TIMEOUT" || {
        log_error "Cluster 1: Garage pods failed to start"
        kubectl logs deployment/garage-operator -n "$NAMESPACE" --tail=30
        exit 1
    }

    use_cluster "$CLUSTER2_NAME"
    wait_for_pods_ready "garage.rajsingh.info/cluster=garage" 2 "$TIMEOUT" || {
        log_error "Cluster 2: Garage pods failed to start"
        kubectl logs deployment/garage-operator -n "$NAMESPACE" --tail=30
        exit 1
    }

    # Step 8: Configure remoteClusters for operator-driven federation
    log_info "=== Step 8: Configuring remoteClusters for operator-driven federation ==="

    # Get pod IPs for cross-cluster admin API access
    use_cluster "$CLUSTER1_NAME"
    CLUSTER1_POD_IP=$(pod_ip_for_selector "$NAMESPACE" "garage.rajsingh.info/cluster=garage" || true)
    CLUSTER1_ADMIN_ENDPOINT="http://${CLUSTER1_POD_IP}:3903"
    log_info "  Cluster 1 admin endpoint: $CLUSTER1_ADMIN_ENDPOINT"

    use_cluster "$CLUSTER2_NAME"
    CLUSTER2_POD_IP=$(pod_ip_for_selector "$NAMESPACE" "garage.rajsingh.info/cluster=garage" || true)
    CLUSTER2_ADMIN_ENDPOINT="http://${CLUSTER2_POD_IP}:3903"
    log_info "  Cluster 2 admin endpoint: $CLUSTER2_ADMIN_ENDPOINT"

    # Configure bidirectional remoteClusters
    patch_garage_with_remote_clusters "$CLUSTER1_NAME" "garage" "cluster2" "zone-b" "$CLUSTER2_ADMIN_ENDPOINT"
    patch_garage_with_remote_clusters "$CLUSTER2_NAME" "garage" "cluster1" "zone-a" "$CLUSTER1_ADMIN_ENDPOINT"

    log_info "=== Step 9: Waiting for operator federation ==="
    log_info "  Operator will connect clusters and update layout automatically"
    log_info "  Waiting for federation to establish..."
    if ! wait_for_federated_peers 180 3; then
        log_warn "Federation did not reach the expected peer count before the test phase"
    fi

    # ========================================================================
    # Run Tests
    # ========================================================================

    echo ""
    log_info "=========================================="
    log_info "    RUNNING MULTI-CLUSTER TESTS"
    log_info "=========================================="

    echo ""
    log_info "--- Cluster Creation Tests ---"
    run_e2e_test test_cluster1_creation
    run_e2e_test test_cluster2_creation

    echo ""
    log_info "--- Cluster Health Tests ---"
    run_e2e_test test_cluster1_health
    run_e2e_test test_cluster2_health

    echo ""
    log_info "--- Zone Configuration Tests ---"
    run_e2e_test test_zone_distribution
    run_e2e_test test_self_connection_skip

    echo ""
    log_info "--- Cross-Cluster Connectivity Tests ---"
    run_e2e_test test_cross_cluster_connectivity

    echo ""
    log_info "--- Automatic Layout Management Tests ---"
    run_e2e_test test_automatic_layout_management

    echo ""
    log_info "--- Resource Creation Tests ---"
    run_e2e_test test_bucket_creation_cluster1
    run_e2e_test test_bucket_creation_cluster2
    run_e2e_test test_key_creation_cluster1
    run_e2e_test test_key_creation_cluster2

    echo ""
    log_info "--- Independent Operations Tests ---"
    run_e2e_test test_independent_cluster_operations
    run_e2e_test test_shared_rpc_secret
    run_e2e_test test_cluster_layout_version
    run_e2e_test test_total_node_count

    echo ""
    log_info "--- Admin API Tests ---"
    run_e2e_test test_admin_api_cluster1
    run_e2e_test test_admin_api_cluster2

    echo ""
    log_info "--- Credential Tests ---"
    run_e2e_test test_credential_validation
    run_e2e_test test_key_sync_across_clusters
    run_e2e_test test_credential_drift

    echo ""
    log_info "--- Gateway Cluster Tests ---"
    run_e2e_test test_gateway_cluster_creation
    run_e2e_test test_gateway_in_layout
    run_e2e_test test_gateway_connection_status
    run_e2e_test test_gateway_s3_operations
    run_e2e_test test_gateway_does_not_remove_storage_nodes
    run_e2e_test test_gateway_cleanup
    run_e2e_test test_gateway_cleanup_layout

    echo ""
    log_info "--- Manual Mode with GarageNodes Multi-Cluster Tests ---"
    run_e2e_test test_manual_mode_multicluster_setup
    run_e2e_test test_manual_mode_cluster_creation_multicluster
    run_e2e_test test_manual_mode_garagenodes_creation
    run_e2e_test test_manual_mode_pods_running
    run_e2e_test test_manual_mode_nodes_in_layout
    run_e2e_test test_manual_mode_cluster_health_multicluster
    run_e2e_test test_manual_mode_federation_multicluster
    run_e2e_test test_manual_mode_bucket_operations_multicluster
    run_e2e_test test_manual_mode_cleanup_multicluster

    echo ""
    log_info "--- Single-Replica Federation Test (Regression) ---"
    run_e2e_test test_single_replica_federation

    # Print cluster status
    echo ""
    log_info "=== Cluster 1 Status ==="
    use_cluster "$CLUSTER1_NAME"
    kubectl get garagecluster,garagebucket,garagekey -n "$NAMESPACE" 2>/dev/null || true

    echo ""
    log_info "=== Cluster 2 Status ==="
    use_cluster "$CLUSTER2_NAME"
    kubectl get garagecluster,garagebucket,garagekey -n "$NAMESPACE" 2>/dev/null || true

    # Print summary
    print_summary
}

main "$@"
