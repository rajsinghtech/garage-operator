#!/bin/bash
set -euo pipefail

# Single-cluster E2E test script for garage-operator
# Usage: ./hack/e2e-cluster.sh [--no-cleanup] [--skip-build]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=hack/e2e-common.sh
source "$SCRIPT_DIR/e2e-common.sh"
CLUSTER_NAME="garage-e2e-test"
NAMESPACE="garage-operator-system"
TIMEOUT=120

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
CONFIG_CHANGE_INITIAL_HASH=""
CONFIG_CHANGE_APPLIED=false
SCALE_DOWN_NODE_ID=""
CLUSTER_CREATED=false

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

E2E_KUBECONFIG_DIR=$(mktemp -d "${TMPDIR:-/tmp}/garage-e2e-kubeconfig.XXXXXX")
export KUBECONFIG="$E2E_KUBECONFIG_DIR/config"
CLUSTER_UID=""

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
    if [ "$CLUSTER_CREATED" != true ]; then
        return 0
    fi
    if [ "$CLEANUP" = true ]; then
        local clusters live_uid
        if ! clusters=$(kind get clusters 2>/dev/null); then
            log_error "Could not enumerate Kind clusters; preserving kubeconfig $KUBECONFIG"
            return 1
        fi
        if ! grep -Fqx -- "$CLUSTER_NAME" <<<"$clusters"; then
            log_warn "Kind cluster '$CLUSTER_NAME' is already absent; removing its dedicated kubeconfig"
            rm -f "$KUBECONFIG"
            rmdir "$E2E_KUBECONFIG_DIR" 2>/dev/null || true
            return 0
        fi
        live_uid=$(kubectl --context "kind-$CLUSTER_NAME" get namespace kube-system \
            -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
        if [ -z "$CLUSTER_UID" ] || [ "$live_uid" != "$CLUSTER_UID" ]; then
            log_error "Refusing to delete '$CLUSTER_NAME': live kube-system UID does not match this run"
            return 1
        fi
        dump_debug_info "$CLUSTER_NAME"
        log_info "Cleaning up kind cluster..."
        if ! kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null; then
            log_error "Failed to delete kind cluster '$CLUSTER_NAME'; preserving kubeconfig $KUBECONFIG"
            return 1
        fi
        if ! kind_cluster_is_absent "$CLUSTER_NAME"; then
            log_error "Kind cluster '$CLUSTER_NAME' still exists or could not be verified absent; preserving kubeconfig $KUBECONFIG"
            return 1
        fi
        rm -f "$KUBECONFIG"
        rmdir "$E2E_KUBECONFIG_DIR" 2>/dev/null || true
    else
        log_warn "Skipping cleanup. Cluster '$CLUSTER_NAME' still running."
        log_info "Kubeconfig: $KUBECONFIG"
        log_info "To delete: kind delete cluster --name $CLUSTER_NAME"
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

wait_for_exact_ready_pods() {
    local selector=$1
    local expected_count=$2
    local timeout=$3

    log_info "Waiting for exactly $expected_count Ready pods with selector '$selector'..."
    local end_time=$((SECONDS + timeout))
    while [ $SECONDS -lt $end_time ]; do
        local snapshot total ready
        if snapshot=$(kubectl get pods -n "$NAMESPACE" -l "$selector" -o json \
            --request-timeout=5s 2>/dev/null); then
            total=$(jq -r '[.items[] | select(.metadata.deletionTimestamp == null)] | length' <<< "$snapshot")
            ready=$(jq -r '[.items[]
                | select(.metadata.deletionTimestamp == null)
                | select(.status.phase == "Running")
                | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))]
                | length' <<< "$snapshot")
            if [ "$total" = "$expected_count" ] && [ "$ready" = "$expected_count" ]; then
                log_info "Exactly $expected_count pods are Ready"
                return 0
            fi
        else
            log_warn "API read failed while waiting for the exact Ready pod set; retrying"
        fi
        sleep 2
    done

    log_error "Timeout waiting for exactly $expected_count Ready pods"
    kubectl get pods -n "$NAMESPACE" -l "$selector" -o wide || true
    return 1
}

wait_for_resource_deleted() {
    local resource_type=$1
    local resource_name=$2
    local timeout=$3

    log_info "Waiting for $resource_type/$resource_name to be deleted..."
    local end_time=$((SECONDS + timeout))

    while [ $SECONDS -lt $end_time ]; do
        local resource
        if resource=$(kubectl get "$resource_type" "$resource_name" -n "$NAMESPACE" \
            --ignore-not-found -o name --request-timeout=5s 2>/dev/null); then
            if [ -z "$resource" ]; then
                log_info "$resource_type/$resource_name deleted"
                return 0
            fi
        else
            log_warn "API read failed while waiting for $resource_type/$resource_name deletion; retrying"
        fi
        sleep 2
    done

    log_error "Timeout waiting for $resource_type/$resource_name to be deleted"
    return 1
}

delete_test_garagenode() {
    local node_name=$1
    local output
    if ! output=$(kubectl delete garagenode "$node_name" -n "$NAMESPACE" \
        --ignore-not-found --wait=false --request-timeout=15s 2>&1); then
        log_error "Failed to request GarageNode/$node_name cleanup: $output"
        return 1
    fi
    wait_for_resource_deleted garagenode "$node_name" 60
}

assert_external_garagenode_fails_closed() {
    local node_name=$1
    local expected_node_id=$2
    local description=$3
    local phase=""
    local generation=""
    local ready_status=""
    local ready_reason=""
    local ready_observed_generation=""
    local status_node_id=""
    local in_layout=""
    local role_matches="-1"
    local staged_matches="-1"
    local status_converged=false
    local layout_proven=false
    local end_time=$((SECONDS + 60))

    while [ "$SECONDS" -lt "$end_time" ]; do
        local snapshot
        snapshot=$(kubectl get garagenode "$node_name" -n "$NAMESPACE" -o json 2>/dev/null | \
            jq -r '
                (.status.conditions // [] | map(select(.type == "Ready")) | last // {}) as $ready |
                [
                    .status.phase // "",
                    (.metadata.generation // ""),
                    $ready.status // "",
                    $ready.reason // "",
                    ($ready.observedGeneration // ""),
                    .status.nodeId // "",
                    (.status.inLayout // false)
                ] | map(tostring) | join("|")
            ' 2>/dev/null || true)
        IFS='|' read -r phase generation ready_status ready_reason \
            ready_observed_generation status_node_id in_layout <<< "$snapshot"
        if [ "$phase" = "Failed" ] && [ -n "$generation" ] && \
            [ "$ready_status" = "False" ] && [ "$ready_reason" = "ReconcileFailed" ] && \
            [ "$ready_observed_generation" = "$generation" ] && \
            [ -z "$status_node_id" ] && [ "$in_layout" = "false" ]; then
            status_converged=true
            break
        fi
        sleep 3
    done

    if [ "$status_converged" = true ]; then
        end_time=$((SECONDS + 60))
        while [ "$SECONDS" -lt "$end_time" ]; do
            local layout_snapshot layout_info
            layout_info=$(garage_admin_get "/v2/GetClusterLayout" 2>/dev/null || true)
            layout_snapshot=$(jq -r --arg id "$expected_node_id" '
                [
                    ([.roles[]? | select(.id == $id)] | length),
                    ([.stagedRoleChanges[]? | select(.id == $id)] | length)
                ] | map(tostring) | join("|")
            ' <<< "$layout_info" 2>/dev/null || true)
            IFS='|' read -r role_matches staged_matches <<< "$layout_snapshot"
            if [ "$role_matches" = "0" ] && [ "$staged_matches" = "0" ]; then
                layout_proven=true
                break
            fi
            sleep 3
        done
    fi

    if ! delete_test_garagenode "$node_name"; then
        test_fail "$description fixture could not be cleaned up"
        return 1
    fi
    if [ "$status_converged" = true ] && [ "$layout_proven" = true ]; then
        test_pass "$description failed closed without publishing its fake identity"
        return 0
    fi
    test_fail "$description did not fail closed (phase: ${phase:-missing}, generation: ${ready_observed_generation:-missing}/${generation:-missing}, Ready: ${ready_status:-missing}/${ready_reason:-missing}, status nodeId: ${status_node_id:-empty}, inLayout: ${in_layout:-missing}, layout matches: ${role_matches:-unavailable}, staged matches: ${staged_matches:-unavailable})"
    return 1
}

garage_admin_status() {
    local path=$1
    local port token status pf_pid log_file

    if ! token=$(kubectl get secret garage-admin-token -n "$NAMESPACE" \
        -o 'go-template={{ index .data "admin-token" | base64decode }}'); then
        return 1
    fi
    if ! start_port_forward service/garage 3903 "$NAMESPACE" 30; then
        return 1
    fi
    pf_pid=$PORT_FORWARD_PID
    port=$PORT_FORWARD_PORT
    log_file=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$port/health" 30 "$log_file"; then
        stop_port_forward "$pf_pid" "$log_file"
        return 1
    fi
    status=$(curl --silent --show-error --connect-timeout 5 --max-time 10 \
        --output /dev/null --write-out '%{http_code}' \
        --header "Authorization: Bearer $token" \
        "http://127.0.0.1:$port$path") || {
        stop_port_forward "$pf_pid" "$log_file"
        return 1
    }
    stop_port_forward "$pf_pid" "$log_file"
    printf '%s\n' "$status"
}

garage_admin_get() {
    local path=$1
    local port token body pf_pid log_file

    if ! token=$(kubectl get secret garage-admin-token -n "$NAMESPACE" \
        -o 'go-template={{ index .data "admin-token" | base64decode }}'); then
        return 1
    fi
    if ! start_port_forward service/garage 3903 "$NAMESPACE" 30; then
        return 1
    fi
    pf_pid=$PORT_FORWARD_PID
    port=$PORT_FORWARD_PORT
    log_file=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$port/health" 30 "$log_file"; then
        stop_port_forward "$pf_pid" "$log_file"
        return 1
    fi
    if ! body=$(curl --fail --silent --show-error --connect-timeout 5 --max-time 10 \
        --header "Authorization: Bearer $token" \
        "http://127.0.0.1:$port$path"); then
        stop_port_forward "$pf_pid" "$log_file"
        return 1
    fi
    stop_port_forward "$pf_pid" "$log_file"
    printf '%s\n' "$body"
}

wait_for_garage_admin_status() {
    local path=$1
    local expected=$2
    local timeout=$3
    local status=""
    local end_time=$((SECONDS + timeout))

    while [ $SECONDS -lt $end_time ]; do
        status=$(garage_admin_status "$path" 2>/dev/null || true)
        if [ "$status" = "$expected" ]; then
            return 0
        fi
        sleep 2
    done
    log_error "Garage Admin API $path did not return HTTP $expected (last: ${status:-unavailable})"
    return 1
}

wait_for_empty_garage_admin_list() {
    local path=$1
    local resource_name=$2
    local timeout=$3
    local body=""
    local count="unavailable"
    local end_time=$((SECONDS + timeout))

    while [ $SECONDS -lt $end_time ]; do
        body=$(garage_admin_get "$path" 2>/dev/null || true)
        if count=$(jq -r \
            'if type == "array" then length else error("expected an array") end' \
            <<<"$body" 2>/dev/null); then
            if [ "$count" = "0" ]; then
                return 0
            fi
        else
            count="unavailable"
        fi
        sleep 2
    done
    log_error "Garage Admin API $path still reported $resource_name (last count: $count)"
    return 1
}

s3_head_bucket_result() {
    local job_name=$1
    local access_key=$2
    local secret_key=$3
    local result=""

    kubectl delete job "$job_name" -n "$NAMESPACE" \
        --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1 || true
    cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata:
  name: $job_name
  namespace: $NAMESPACE
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 300
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: aws-cli
        image: amazon/aws-cli:2.27.41@sha256:bc6b7bba44ce38f9604ede49c584824af919047ea03fbcc7c7610671fdef95d8
        env:
        - name: AWS_ACCESS_KEY_ID
          value: "$access_key"
        - name: AWS_SECRET_ACCESS_KEY
          value: "$secret_key"
        - name: AWS_DEFAULT_REGION
          value: garage
        - name: AWS_PAGER
          value: ""
        command:
        - aws
        - --endpoint-url
        - http://garage.${NAMESPACE}.svc.cluster.local:3900
        - s3api
        - head-bucket
        - --bucket
        - test-bucket
        securityContext:
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
EOF

    local end_time=$((SECONDS + 120))
    while [ $SECONDS -lt $end_time ]; do
        local succeeded failed
        succeeded=$(kubectl get job "$job_name" -n "$NAMESPACE" \
            -o jsonpath='{.status.succeeded}' 2>/dev/null || true)
        failed=$(kubectl get job "$job_name" -n "$NAMESPACE" \
            -o jsonpath='{.status.failed}' 2>/dev/null || true)
        if [ "$succeeded" = "1" ]; then
            result=success
            break
        fi
        if [[ "${failed:-0}" =~ ^[1-9][0-9]*$ ]]; then
            local job_logs
            if ! job_logs=$(kubectl logs job/"$job_name" -n "$NAMESPACE" \
                --all-containers=true 2>&1); then
                log_error "Could not capture aws-cli logs from S3 credential check Job/$job_name" >&2
                printf '%s\n' "$job_logs" >&2
                kubectl describe job "$job_name" -n "$NAMESPACE" >&2 || true
                result=error
            elif grep -Eqi \
                'InvalidAccessKeyId|AccessDenied|Forbidden|(^|[^[:digit:]])403([^[:digit:]]|$)' \
                <<<"$job_logs"; then
                result=denied
            else
                log_error "S3 credential check Job/$job_name failed without an authentication rejection" >&2
                printf '%s\n' "$job_logs" >&2
                kubectl describe job "$job_name" -n "$NAMESPACE" >&2 || true
                result=error
            fi
            break
        fi
        sleep 2
    done
    if [ -z "$result" ]; then
        kubectl describe job "$job_name" -n "$NAMESPACE" >&2 || true
        kubectl logs job/"$job_name" -n "$NAMESPACE" >&2 || true
        result=timeout
    fi
    kubectl delete job "$job_name" -n "$NAMESPACE" \
        --ignore-not-found --wait=false --request-timeout=15s >/dev/null 2>&1 || true
    printf '%s\n' "$result"
}

wait_for_storage_rollout_converged() {
    local cluster_name=$1
    local timeout=$2

    log_info "Waiting for GarageCluster/$cluster_name current storage generation to converge..."
    local end_time=$((SECONDS + timeout))
    while [ $SECONDS -lt $end_time ]; do
        local snapshot generation observed status reason
        snapshot=$(kubectl get garagecluster "$cluster_name" -n "$NAMESPACE" \
            -o 'jsonpath={.metadata.generation}{"|"}{.status.conditions[?(@.type=="StorageRolloutReady")].observedGeneration}{"|"}{.status.conditions[?(@.type=="StorageRolloutReady")].status}{"|"}{.status.conditions[?(@.type=="StorageRolloutReady")].reason}' 2>/dev/null || true)
        IFS='|' read -r generation observed status reason <<< "$snapshot"
        if [ -n "$generation" ] && [ "$observed" = "$generation" ] && \
           [ "$status" = "True" ] && [ "$reason" = "Converged" ]; then
            log_info "Garage storage rollout is converged at generation $generation"
            return 0
        fi
        sleep 5
    done

    log_error "Timeout waiting for GarageCluster/$cluster_name current storage generation to converge"
    kubectl get garagecluster "$cluster_name" -n "$NAMESPACE" -o yaml 2>/dev/null | tail -n 120 || true
    return 1
}

wait_for_storage_topology_converged() {
    local cluster_name=$1
    local timeout=$2

    log_info "Waiting for GarageCluster/$cluster_name current storage topology to converge..."
    local end_time=$((SECONDS + timeout))
    while [ $SECONDS -lt $end_time ]; do
        local snapshot generation observed status reason
        snapshot=$(kubectl get garagecluster "$cluster_name" -n "$NAMESPACE" \
            -o 'jsonpath={.metadata.generation}{"|"}{.status.conditions[?(@.type=="StorageTopologyReady")].observedGeneration}{"|"}{.status.conditions[?(@.type=="StorageTopologyReady")].status}{"|"}{.status.conditions[?(@.type=="StorageTopologyReady")].reason}' 2>/dev/null || true)
        IFS='|' read -r generation observed status reason <<< "$snapshot"
        if [ -n "$generation" ] && [ "$observed" = "$generation" ] && \
           [ "$status" = "True" ] && [ "$reason" = "Converged" ]; then
            log_info "Garage storage topology is converged at generation $generation"
            return 0
        fi
        sleep 5
    done

    log_error "Timeout waiting for GarageCluster/$cluster_name current storage topology to converge"
    kubectl get garagecluster "$cluster_name" -n "$NAMESPACE" -o yaml 2>/dev/null | tail -n 120 || true
    return 1
}

wait_for_garage_node_committed() {
    local node_name=$1
    local timeout=$2

    log_info "Waiting for GarageNode/$node_name current identity to join the committed layout..."
    local end_time=$((SECONDS + timeout))
    while [ $SECONDS -lt $end_time ]; do
        local snapshot generation observed node_id connected in_layout
        snapshot=$(kubectl get garagenode "$node_name" -n "$NAMESPACE" \
            -o 'jsonpath={.metadata.generation}{"|"}{.status.observedGeneration}{"|"}{.status.nodeId}{"|"}{.status.connected}{"|"}{.status.inLayout}' 2>/dev/null || true)
        IFS='|' read -r generation observed node_id connected in_layout <<< "$snapshot"
        if [ -n "$generation" ] && [ "$observed" = "$generation" ] && \
           [ -n "$node_id" ] && [ "$connected" = "true" ] && [ "$in_layout" = "true" ]; then
            return 0
        fi
        sleep 5
    done

    log_error "Timeout waiting for GarageNode/$node_name to join the committed layout"
    kubectl get garagenode "$node_name" -n "$NAMESPACE" -o yaml 2>/dev/null | tail -n 100 || true
    return 1
}

get_primary_storage_configmap() {
    kubectl get statefulset garage-storage-0 -n "$NAMESPACE" \
        -o 'jsonpath={.spec.template.spec.volumes[?(@.name=="config")].configMap.name}' 2>/dev/null || true
}

get_primary_storage_config() {
    local config_name
    config_name=$(get_primary_storage_configmap)
    if [ -n "$config_name" ]; then
        kubectl get configmap "$config_name" -n "$NAMESPACE" \
            -o 'jsonpath={.data.garage\.toml}' 2>/dev/null || true
    fi
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
    kubectl get garagecluster garage -n "$NAMESPACE" \
        -o jsonpath='{.status.health.status}' --request-timeout=5s 2>/dev/null || echo "unknown"
}

get_connected_nodes() {
    kubectl get garagecluster garage -n "$NAMESPACE" \
        -o jsonpath='{.status.health.connectedNodes}' --request-timeout=5s 2>/dev/null || echo "0"
}

wait_for_cluster_replicas() {
    local cluster_name=$1
    local expected_replicas=$2
    local timeout=$3
    local phase="" ready=""

    log_info "Waiting for GarageCluster/$cluster_name to be Running with $expected_replicas ready replicas (timeout: ${timeout}s)..."
    local end_time=$((SECONDS + timeout))
    while [ $SECONDS -lt $end_time ]; do
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

# Poll for ALL terminal readiness signals at once: phase, admin-API health, node
# count, and partition quorum must hold simultaneously before returning. This avoids
# the sequential-wait race where a fast-converging field (health, read straight from
# the Garage Admin API) is asserted before a slow one (phase, which derives from child
# GarageNode .status.connected refreshed on the GarageNode controller's 1-min requeue).
# Waiting on them separately with a short second window is what flaked #213/#214/#215.
wait_for_cluster_fully_ready() {
    local timeout=${1:-360}
    local end_time=$((SECONDS + timeout))

    log_info "Waiting for cluster to be fully ready (phase=Running, health=healthy, 3/3 nodes, partitions in quorum; timeout: ${timeout}s)..."
    while [ $SECONDS -lt $end_time ]; do
        local phase health connected pq pt
        phase=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
        health=$(get_cluster_health)
        connected=$(get_connected_nodes)
        pq=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.health.partitionsQuorum}' 2>/dev/null || echo "0")
        pt=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.health.partitions}' 2>/dev/null || echo "0")
        if [ "$phase" = "Running" ] && [ "$health" = "healthy" ] && [ "$connected" = "3" ] && [ -n "$pt" ] && [ "$pt" != "0" ] && [ "$pq" = "$pt" ]; then
            return 0
        fi
        sleep 5
    done
    return 1
}

# ============================================================================
# Test Functions
# ============================================================================

test_cluster_creation() {
    log_test "Testing GarageCluster creation..."

    if wait_for_cluster_replicas garage 3 120; then
        test_pass "GarageCluster created with 3 ready replicas"
        return 0
    fi
    test_fail "GarageCluster creation failed"
    return 1
}

test_cluster_health() {
    log_test "Testing cluster health..."

    # Phase, connected-node count, and partition quorum are published by
    # different reconciliation observations. Wait for the complete snapshot so
    # a healthy status cannot race a stale topology field.
    if wait_for_cluster_fully_ready 120; then
        local health connected partitions_quorum partitions_total
        health=$(get_cluster_health)
        connected=$(get_connected_nodes)
        partitions_quorum=$(kubectl get garagecluster garage -n "$NAMESPACE" \
            -o jsonpath='{.status.health.partitionsQuorum}' --request-timeout=5s 2>/dev/null || echo "0")
        partitions_total=$(kubectl get garagecluster garage -n "$NAMESPACE" \
            -o jsonpath='{.status.health.partitions}' --request-timeout=5s 2>/dev/null || echo "0")
        test_pass "Cluster health: $health, nodes: $connected, partitions: $partitions_quorum/$partitions_total"
        return 0
    fi

    local health connected partitions_quorum partitions_total
    health=$(get_cluster_health)
    connected=$(get_connected_nodes)
    partitions_quorum=$(kubectl get garagecluster garage -n "$NAMESPACE" \
        -o jsonpath='{.status.health.partitionsQuorum}' --request-timeout=5s 2>/dev/null || echo "0")
    partitions_total=$(kubectl get garagecluster garage -n "$NAMESPACE" \
        -o jsonpath='{.status.health.partitions}' --request-timeout=5s 2>/dev/null || echo "0")
    test_fail "Cluster health check failed: health=$health, nodes=$connected, partitions=$partitions_quorum/$partitions_total"
    return 1
}

test_bucket_creation() {
    log_test "Testing GarageBucket creation..."

    if check_resource_phase "garagebucket" "test-bucket" "Ready" 60; then
        # Verify bucket exists in Garage
        local bucket_id
        bucket_id=$(kubectl get garagebucket test-bucket -n "$NAMESPACE" -o jsonpath='{.status.bucketId}')
        if [ -n "$bucket_id" ]; then
            test_pass "GarageBucket created with ID: $bucket_id"
            return 0
        fi
    fi
    test_fail "GarageBucket creation failed"
    return 1
}

test_key_creation() {
    log_test "Testing GarageKey creation..."

    if check_resource_phase "garagekey" "test-key" "Ready" 60; then
        local access_key
        access_key=$(kubectl get garagekey test-key -n "$NAMESPACE" -o jsonpath='{.status.accessKeyId}')
        if [ -n "$access_key" ]; then
            test_pass "GarageKey created with AccessKeyID: $access_key"
            return 0
        fi
    fi
    test_fail "GarageKey creation failed"
    return 1
}

test_secret_creation() {
    log_test "Testing Secret creation for GarageKey..."

    # Wait for key to be Ready first (secret is only created when key is ready)
    if ! check_resource_phase "garagekey" "test-key" "Ready" 60; then
        test_fail "Secret creation failed (key not Ready)"
        return 1
    fi

    if kubectl get secret test-s3-credentials -n "$NAMESPACE" &>/dev/null; then
        local keys
        keys=$(kubectl get secret test-s3-credentials -n "$NAMESPACE" -o jsonpath='{.data}' | jq -r 'keys | join(",")')
        if [[ "$keys" == *"access-key-id"* ]] && [[ "$keys" == *"secret-access-key"* ]]; then
            test_pass "Secret created with keys: $keys"
            return 0
        fi
    fi
    test_fail "Secret creation failed"
    return 1
}

test_s3_connectivity() {
    log_test "Testing S3 API connectivity..."

    # Port-forward and test
    if ! start_port_forward svc/garage 3900 "$NAMESPACE" 30; then
        test_fail "S3 port-forward did not start"
        return 1
    fi
    local pf_pid=$PORT_FORWARD_PID pf_port=$PORT_FORWARD_PORT pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$pf_port/" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "S3 port-forward did not become ready"
        return 1
    fi

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$pf_port/" 2>/dev/null || echo "000")
    stop_port_forward "$pf_pid" "$pf_log"

    # 403 is expected (no auth), 200 would also be fine
    if [ "$http_code" = "403" ] || [ "$http_code" = "200" ]; then
        test_pass "S3 API responding (HTTP $http_code)"
        return 0
    fi
    test_fail "S3 API not responding (HTTP $http_code)"
    return 1
}

test_admin_api_connectivity() {
    log_test "Testing Admin API connectivity..."

    if ! start_port_forward svc/garage 3903 "$NAMESPACE" 30; then
        test_fail "Admin API port-forward did not start"
        return 1
    fi
    local pf_pid=$PORT_FORWARD_PID pf_port=$PORT_FORWARD_PORT pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$pf_port/health" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Admin API port-forward did not become ready"
        return 1
    fi

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$pf_port/health" 2>/dev/null || echo "000")
    stop_port_forward "$pf_pid" "$pf_log"

    if [ "$http_code" = "200" ]; then
        test_pass "Admin API responding (HTTP $http_code)"
        return 0
    fi
    test_fail "Admin API not responding (HTTP $http_code)"
    return 1
}

test_bucket_quotas() {
    log_test "Testing bucket quotas..."

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: quota-test-bucket
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  globalAlias: quota-test-bucket
  quotas:
    maxSize: 500Mi
    maxObjects: 500
EOF

    local phase=""
    local size_limit=""
    local object_limit=""
    local quota_deadline=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$quota_deadline" ]; do
        local snapshot
        snapshot=$(kubectl get garagebucket quota-test-bucket -n "$NAMESPACE" -o json 2>/dev/null | \
            jq -r '[.status.phase // "", (.status.quotaUsage.sizeLimit // ""), (.status.quotaUsage.objectLimit // "")] | map(tostring) | join("|")' 2>/dev/null || true)
        IFS='|' read -r phase size_limit object_limit <<< "$snapshot"
        if [ "$phase" = "Ready" ] && [ "$size_limit" = "524288000" ] && \
            [ "$object_limit" = "500" ]; then
            test_pass "Bucket reports the exact configured quotas"
            return 0
        fi
        sleep 3
    done
    test_fail "Bucket quotas did not converge (phase: ${phase:-missing}, sizeLimit: ${size_limit:-missing}, objectLimit: ${object_limit:-missing})"
    return 1
}

test_key_permissions() {
    log_test "Testing key bucket permissions..."

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: multi-bucket-key
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  name: multi-bucket-access
  bucketPermissions:
    - bucketRef:
        name: test-bucket
      read: true
      write: false
    - bucketRef:
        name: quota-test-bucket
      read: true
      write: true
      owner: true
  secretTemplate:
    name: multi-bucket-credentials
EOF

    local phase=""
    local permission_count=0
    local permission_deadline=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$permission_deadline" ]; do
        local snapshot
        snapshot=$(kubectl get garagekey multi-bucket-key -n "$NAMESPACE" -o json 2>/dev/null || true)
        phase=$(echo "$snapshot" | jq -r '.status.phase // ""' 2>/dev/null || true)
        permission_count=$(echo "$snapshot" | jq -r '[
            .status.buckets[]? |
            select(
                (.globalAlias == "test-bucket" and .read == true and .write == false and .owner == false) or
                (.globalAlias == "quota-test-bucket" and .read == true and .write == true and .owner == true)
            )
        ] | length' 2>/dev/null || echo "0")
        if [ "$phase" = "Ready" ] && [ "$permission_count" = "2" ]; then
            test_pass "Key reports both exact bucket permission sets"
            return 0
        fi
        sleep 3
    done
    test_fail "Key permissions did not converge (phase: ${phase:-missing}, matching buckets: $permission_count/2)"
    return 1
}

test_bucket_deletion() {
    log_test "Testing GarageBucket deletion..."

    # Create a bucket to delete
    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: delete-test-bucket
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  globalAlias: delete-test-bucket
EOF

    if ! check_resource_phase "garagebucket" "delete-test-bucket" "Ready" 60; then
        test_fail "Could not create bucket for deletion test"
        return 1
    fi

    local bucket_id
    bucket_id=$(kubectl get garagebucket delete-test-bucket -n "$NAMESPACE" \
        -o jsonpath='{.status.bucketId}' 2>/dev/null || true)
    if [ -z "$bucket_id" ] || \
       ! wait_for_garage_admin_status "/v2/GetBucketInfo?id=$bucket_id" 200 60; then
        test_fail "Could not prove the exact Garage bucket existed before deletion"
        kubectl delete garagebucket delete-test-bucket -n "$NAMESPACE" \
            --wait=false --request-timeout=15s 2>/dev/null || true
        return 1
    fi

    # Delete the bucket
    kubectl delete garagebucket delete-test-bucket -n "$NAMESPACE" \
        --wait=true --timeout=120s

    if wait_for_resource_deleted "garagebucket" "delete-test-bucket" 60 && \
       wait_for_garage_admin_status "/v2/GetBucketInfo?id=$bucket_id" 404 120; then
        test_pass "GarageBucket deletion removed the exact Garage bucket $bucket_id"
        return 0
    fi
    test_fail "GarageBucket deletion did not remove the exact Garage bucket $bucket_id"
    return 1
}

test_key_deletion() {
    log_test "Testing GarageKey deletion..."

    # Create a key to delete
    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: delete-test-key
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  name: delete-test-key
  bucketPermissions:
    - bucketRef:
        name: test-bucket
      read: true
  secretTemplate:
    name: delete-test-credentials
EOF

    if ! check_resource_phase "garagekey" "delete-test-key" "Ready" 60; then
        test_fail "Could not create key for deletion test"
        return 1
    fi

    local access_key secret_key pre_delete_result
    access_key=$(kubectl get garagekey delete-test-key -n "$NAMESPACE" \
        -o jsonpath='{.status.accessKeyId}' 2>/dev/null || true)
    secret_key=$(kubectl get secret delete-test-credentials -n "$NAMESPACE" \
        -o 'go-template={{ index .data "secret-access-key" | base64decode }}' 2>/dev/null || true)
    if [ -z "$access_key" ] || [ -z "$secret_key" ] || \
       ! wait_for_garage_admin_status "/v2/GetKeyInfo?id=$access_key" 200 60; then
        test_fail "Could not prove the exact Garage key and copied credentials before deletion"
        kubectl delete garagekey delete-test-key -n "$NAMESPACE" \
            --wait=false --request-timeout=15s 2>/dev/null || true
        return 1
    fi
    pre_delete_result=$(s3_head_bucket_result delete-key-valid "$access_key" "$secret_key")
    if [ "$pre_delete_result" != success ]; then
        test_fail "Copied credentials were not usable before deletion (result: $pre_delete_result)"
        kubectl delete garagekey delete-test-key -n "$NAMESPACE" \
            --wait=false --request-timeout=15s 2>/dev/null || true
        return 1
    fi

    # Delete the key
    kubectl delete garagekey delete-test-key -n "$NAMESPACE" \
        --wait=true --timeout=120s

    if wait_for_resource_deleted "garagekey" "delete-test-key" 60; then
        local secret_deadline=$((SECONDS + 60))
        while [ $SECONDS -lt $secret_deadline ]; do
            if ! kubectl get secret delete-test-credentials -n "$NAMESPACE" >/dev/null 2>&1; then
                break
            fi
            sleep 2
        done
        if kubectl get secret delete-test-credentials -n "$NAMESPACE" >/dev/null 2>&1; then
            test_fail "Secret was not cleaned up"
            return 1
        fi
        if ! wait_for_garage_admin_status "/v2/GetKeyInfo?id=$access_key" 404 120; then
            test_fail "GarageKey deletion left the exact Garage key $access_key active"
            return 1
        fi
        local post_delete_result
        post_delete_result=$(s3_head_bucket_result delete-key-revoked "$access_key" "$secret_key")
        if [ "$post_delete_result" = denied ]; then
            test_pass "GarageKey deletion revoked $access_key, removed its Secret, and invalidated copied credentials"
            return 0
        fi
        test_fail "Copied credentials did not produce the expected authentication rejection after key deletion (result: $post_delete_result)"
        return 1
    fi
    test_fail "GarageKey deletion failed"
    return 1
}

test_scale_subresource() {
    log_test "Testing scale subresource (kubectl scale)..."

    if ! wait_for_storage_rollout_converged garage 600; then
        test_fail "Scale subresource: preceding storage generation did not converge"
        return 1
    fi

    # Verify status.selector is populated
    local selector
    selector=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.selector}')
    if [ -z "$selector" ]; then
        test_fail "status.selector not populated"
        return 1
    fi
    log_info "  status.selector=$selector"

    # Verify status.storageReplicas is populated (v1beta2 scale subresource)
    local status_replicas
    status_replicas=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.storageReplicas}')
    if [ "$status_replicas" != "3" ]; then
        test_fail "status.storageReplicas expected 3 but got $status_replicas"
        return 1
    fi

    # Test kubectl scale up via scale subresource
    kubectl scale garagecluster garage -n "$NAMESPACE" --replicas=4
    local spec_replicas
    spec_replicas=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.spec.storage.replicas}')
    if [ "$spec_replicas" != "4" ]; then
        test_fail "kubectl scale did not update spec.replicas (got $spec_replicas)"
        return 1
    fi

    # Wait for the exact additive identity, not merely a fourth Running pod.
    if ! wait_for_exact_ready_pods "garage.rajsingh.info/cluster=garage,garage.rajsingh.info/tier=storage" 4 300; then
        test_fail "Pods did not scale to 4 via scale subresource"
        return 1
    fi
    if ! wait_for_garage_node_committed garage-storage-3 600 || \
       ! wait_for_storage_topology_converged garage 600 || \
       ! wait_for_storage_rollout_converged garage 600; then
        test_fail "Scale subresource: scale-up identity and rollout did not converge"
        return 1
    fi
    if ! SCALE_DOWN_NODE_ID=$(kubectl get garagenode garage-storage-3 -n "$NAMESPACE" -o jsonpath='{.status.nodeId}'); then
        test_fail "Scale subresource: failed to read garage-storage-3's durable Garage identity"
        return 1
    fi
    if [ -z "$SCALE_DOWN_NODE_ID" ]; then
        test_fail "Scale subresource: garage-storage-3 has no durable Garage identity"
        return 1
    fi

    # Leave the committed four-member topology in place. The following test
    # covers patch-based scaling and performs the one required destructive
    # retirement proof.
    test_pass "Scale subresource created an exact committed four-member topology"
    return 0
}

test_cluster_scaling() {
    log_test "Testing patch-based cluster scaling (4 -> 3 replicas)..."

    if ! wait_for_exact_ready_pods "garage.rajsingh.info/cluster=garage,garage.rajsingh.info/tier=storage" 4 300 || \
       ! wait_for_garage_node_committed garage-storage-3 600 || \
       ! wait_for_storage_topology_converged garage 600 || \
       ! wait_for_storage_rollout_converged garage 600; then
        test_fail "Patch scaling: the four-member source topology is not fully committed"
        return 1
    fi

    local source_snapshot
    source_snapshot=$(kubectl get pod garage-storage-3-0 -n "$NAMESPACE" \
        -o 'jsonpath={.metadata.uid}{"|"}{.status.phase}{"|"}{.status.conditions[?(@.type=="Ready")].status}')
    if [[ ! "$source_snapshot" =~ ^[^|]+\|Running\|True$ ]]; then
        test_fail "Patch scaling: exact retirement source Pod is not Running and Ready ($source_snapshot)"
        return 1
    fi
    local source_uid
    source_uid=${source_snapshot%%|*}

    kubectl patch garagecluster garage -n "$NAMESPACE" --type=merge -p '{"spec":{"storage":{"replicas":3}}}'
    local spec_replicas
    spec_replicas=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.spec.storage.replicas}')
    if [ "$spec_replicas" != "3" ]; then
        test_fail "Patch scaling did not update spec.storage.replicas (got $spec_replicas)"
        return 1
    fi

    # Garage v2.3 schedules block GC after 610 seconds. This is the one
    # destructive scaling proof in this suite; 20m covers that exact barrier
    # and reconciliation without weakening it to a generic short timeout.
    log_info "Waiting for GarageNode/garage-storage-3 retirement while its exact source Pod remains live..."
    local retirement_deadline=$((SECONDS + 1200))
    local retired=false
    while [ $SECONDS -lt $retirement_deadline ]; do
        local node_ref
        if ! node_ref=$(kubectl get garagenode garage-storage-3 -n "$NAMESPACE" \
            --ignore-not-found -o name 2>/dev/null); then
            test_fail "Patch scaling: API read failed while proving GarageNode retirement"
            return 1
        fi
        if [ -z "$node_ref" ]; then
            retired=true
            break
        fi

        local current_source
        if ! current_source=$(kubectl get pod garage-storage-3-0 -n "$NAMESPACE" \
            --ignore-not-found \
            -o 'jsonpath={.metadata.uid}{"|"}{.status.phase}{"|"}{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null); then
            test_fail "Patch scaling: API read failed while proving source Pod continuity"
            return 1
        fi
        if [ "$current_source" != "$source_uid|Running|True" ]; then
            # The successful retirement boundary may fall between the
            # GarageNode and Pod reads. Reconfirm the parent before treating a
            # missing source as a safety violation.
            local confirmed_node_ref
            if ! confirmed_node_ref=$(kubectl get garagenode garage-storage-3 -n "$NAMESPACE" \
                --ignore-not-found -o name 2>/dev/null); then
                test_fail "Patch scaling: API read failed while confirming the retirement boundary"
                return 1
            fi
            if [ -z "$confirmed_node_ref" ]; then
                retired=true
                break
            fi
            test_fail "Patch scaling: source Pod changed or became unavailable before GarageNode retirement ($current_source)"
            return 1
        fi
        sleep 10
    done
    if [ "$retired" != true ]; then
        test_fail "Patch scaling: GarageNode/garage-storage-3 did not complete its proven retirement"
        return 1
    fi
    if ! wait_for_exact_ready_pods "garage.rajsingh.info/cluster=garage,garage.rajsingh.info/tier=storage" 3 300 || \
       ! wait_for_storage_topology_converged garage 600 || \
       ! wait_for_storage_rollout_converged garage 600; then
        test_fail "Patch scaling: exact three-member topology did not converge after retirement"
        return 1
    fi

    test_pass "Patch scaling retired the exact fourth identity and converged at three members"
    return 0
}

test_scale_down_layout_cleanup() {
    log_test "Testing layout cleanup after scale down..."

    # Get the admin token
    local admin_token
    admin_token=$(kubectl get secret garage-admin-token -n "$NAMESPACE" -o jsonpath='{.data.admin-token}' 2>/dev/null | base64 -d)
    if [ -z "$admin_token" ]; then
        test_fail "Could not get admin token"
        return 1
    fi

    # Port forward to admin API
    if ! start_port_forward svc/garage 3903 "$NAMESPACE" 30; then
        test_fail "Admin API port-forward did not start"
        return 1
    fi
    local pf_pid=$PORT_FORWARD_PID pf_port=$PORT_FORWARD_PORT pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:${pf_port}/health" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Admin API port-forward did not become ready"
        return 1
    fi

    # Get layout and count nodes
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

    # Count storage nodes in layout (nodes with non-null capacity)
    local storage_nodes
    storage_nodes=$(echo "$layout_info" | jq '[.roles[] | select(.capacity != null)] | length' 2>/dev/null || echo "0")

    # No staged topology mutation may remain after the deletion proof.
    local staged_changes
    staged_changes=$(echo "$layout_info" | jq '(.stagedRoleChanges // []) | length' 2>/dev/null || echo "-1")
    local retired_role_present
    retired_role_present=$(echo "$layout_info" | jq --arg id "$SCALE_DOWN_NODE_ID" \
        '[.roles[] | select(.id == $id)] | length' 2>/dev/null || echo "-1")

    log_info "  Storage nodes in layout: $storage_nodes"
    log_info "  Staged role changes: $staged_changes"

    if [ -z "$SCALE_DOWN_NODE_ID" ]; then
        test_fail "Missing the retired Garage node ID captured during scale-up"
        return 1
    fi
    if [ "$storage_nodes" -eq 3 ] && [ "$staged_changes" -eq 0 ] && [ "$retired_role_present" -eq 0 ]; then
        test_pass "Layout committed exactly three roles with no staged changes or retired identity"
        return 0
    fi

    test_fail "Layout retirement proof failed (nodes: $storage_nodes, staged: $staged_changes, retired role matches: $retired_role_present)"
    echo "Layout response: $layout_info" | head -20
    return 1
}

test_cluster_recovery() {
    log_test "Testing cluster recovery after pod deletion..."

    # Delete a pod
    local pod_to_delete
    pod_to_delete=$(pod_name_for_selector "$NAMESPACE" \
        "garage.rajsingh.info/cluster=garage" || true)
    if [ -z "$pod_to_delete" ]; then
        test_fail "Cluster recovery could not find a Ready Garage Pod to delete"
        return 1
    fi
    kubectl delete pod "$pod_to_delete" -n "$NAMESPACE" \
        --wait=true --timeout=120s

    # Wait for pods to come back up
    if ! wait_for_pods_ready "garage.rajsingh.info/cluster=garage" 3 120; then
        test_fail "Cluster recovery failed - pods did not come back"
        return 1
    fi

    # Wait for every recovery signal, including partition quorum, after gossip
    # and replica synchronization settle.
    # Garage needs time to: 1) detect node is back, 2) re-sync partition data, 3) verify replication
    # This can take several minutes depending on cluster state and network conditions.
    # Note: Recovery time varies significantly based on Garage's gossip settings and partition count.
    if wait_for_cluster_fully_ready 300; then
        test_pass "Cluster recovered after pod deletion"
        return 0
    fi

    local connected
    connected=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.health.connectedNodes}' 2>/dev/null || echo "0")
    local health
    health=$(get_cluster_health)

    test_fail "Cluster recovery failed (health: $health, connected: $connected/3)"
    return 1
}

test_configmap_update() {
    log_test "Testing ConfigMap is managed..."

    local cm_name
    cm_name=$(get_primary_storage_configmap)
    if kubectl get configmap "$cm_name" -n "$NAMESPACE" &>/dev/null; then
        # Verify the controller owner, independent of ownerReferences list order.
        local owner
        owner=$(kubectl get configmap "$cm_name" -n "$NAMESPACE" \
            -o jsonpath='{.metadata.ownerReferences[?(@.controller==true)].kind}')
        if [ "$owner" = "GarageCluster" ]; then
            test_pass "Mounted immutable ConfigMap revision has correct owner reference ($cm_name)"
            return 0
        fi
    fi
    test_fail "Mounted immutable ConfigMap revision test failed (name: ${cm_name:-missing})"
    return 1
}

test_services_created() {
    log_test "Testing Services are created..."

    local headless
    headless=$(kubectl get svc garage-headless -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
    local api_svc
    api_svc=$(kubectl get svc garage -n "$NAMESPACE" -o jsonpath='{.spec.type}' 2>/dev/null)

    if [ "$headless" = "None" ] && [ "$api_svc" = "ClusterIP" ]; then
        test_pass "Headless and API services created correctly"
        return 0
    fi
    test_fail "Services test failed"
    return 1
}

test_status_endpoints() {
    log_test "Testing status endpoints are populated..."

    local s3_endpoint
    s3_endpoint=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.endpoints.s3}')
    local admin_endpoint
    admin_endpoint=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.endpoints.admin}')
    local rpc_endpoint
    rpc_endpoint=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.endpoints.rpc}')

    if [ "$s3_endpoint" = "garage.${NAMESPACE}.svc.cluster.local:3900" ] && \
        [ "$admin_endpoint" = "garage.${NAMESPACE}.svc.cluster.local:3903" ] && \
        [ "$rpc_endpoint" = "garage-headless.${NAMESPACE}.svc.cluster.local:3901" ]; then
        test_pass "Status endpoints populated: s3=$s3_endpoint"
        return 0
    fi
    test_fail "Status endpoints not populated"
    return 1
}

# ============================================================================
# Update Tests
# ============================================================================

test_bucket_quota_update() {
    log_test "Testing bucket quota update..."

    # First ensure bucket is Ready (may need reconciliation after pause-reconcile test)
    if ! check_resource_phase "garagebucket" "quota-test-bucket" "Ready" 60; then
        test_fail "Bucket quota update failed (bucket not Ready before update)"
        return 1
    fi

    # Update quotas on existing bucket
    kubectl patch garagebucket quota-test-bucket -n "$NAMESPACE" --type=merge \
        -p '{"spec":{"quotas":{"maxSize":"1Gi","maxObjects":2000}}}'

    local phase=""
    local observed_generation=""
    local generation=""
    local size_limit=""
    local object_limit=""
    local quota_deadline=$((SECONDS + 90))
    while [ "$SECONDS" -lt "$quota_deadline" ]; do
        local snapshot
        snapshot=$(kubectl get garagebucket quota-test-bucket -n "$NAMESPACE" -o json 2>/dev/null | \
            jq -r '[.status.phase // "", (.status.observedGeneration // ""), .metadata.generation, (.status.quotaUsage.sizeLimit // ""), (.status.quotaUsage.objectLimit // "")] | map(tostring) | join("|")' 2>/dev/null || true)
        IFS='|' read -r phase observed_generation generation size_limit object_limit <<< "$snapshot"
        if [ "$phase" = "Ready" ] && [ "$observed_generation" = "$generation" ] && \
            [ "$size_limit" = "1073741824" ] && [ "$object_limit" = "2000" ]; then
            test_pass "Bucket quota update converged to 1Gi/2000"
            return 0
        fi
        sleep 3
    done
    test_fail "Bucket quota update did not converge (phase: ${phase:-missing}, observedGeneration: ${observed_generation:-missing}/${generation:-missing}, limits: ${size_limit:-missing}/${object_limit:-missing})"
    return 1
}

test_key_permission_update() {
    log_test "Testing key permission update..."

    # First ensure key is Ready (may need reconciliation after pause-reconcile test)
    if ! check_resource_phase "garagekey" "multi-bucket-key" "Ready" 30; then
        test_fail "Key permission update failed (key not Ready before update)"
        return 1
    fi

    # Update permissions on existing key
    kubectl patch garagekey multi-bucket-key -n "$NAMESPACE" --type=merge \
        -p '{"spec":{"bucketPermissions":[{"bucketRef":{"name":"test-bucket"},"read":true,"write":true},{"bucketRef":{"name":"quota-test-bucket"},"read":true,"write":true,"owner":true}]}}'

    local phase=""
    local observed_generation=""
    local generation=""
    local permission_count=0
    local permission_deadline=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$permission_deadline" ]; do
        local snapshot
        snapshot=$(kubectl get garagekey multi-bucket-key -n "$NAMESPACE" -o json 2>/dev/null || true)
        phase=$(echo "$snapshot" | jq -r '.status.phase // ""' 2>/dev/null || true)
        observed_generation=$(echo "$snapshot" | jq -r '.status.observedGeneration // ""' 2>/dev/null || true)
        generation=$(echo "$snapshot" | jq -r '.metadata.generation // ""' 2>/dev/null || true)
        permission_count=$(echo "$snapshot" | jq -r '[
            .status.buckets[]? |
            select(
                (.globalAlias == "test-bucket" and .read == true and .write == true and .owner == false) or
                (.globalAlias == "quota-test-bucket" and .read == true and .write == true and .owner == true)
            )
        ] | length' 2>/dev/null || echo "0")
        if [ "$phase" = "Ready" ] && [ "$observed_generation" = "$generation" ] && \
            [ "$permission_count" = "2" ]; then
            test_pass "Key permission update converged on both buckets"
            return 0
        fi
        sleep 3
    done
    test_fail "Key permission update did not converge (phase: ${phase:-missing}, observedGeneration: ${observed_generation:-missing}/${generation:-missing}, matching buckets: $permission_count/2)"
    return 1
}

# ============================================================================
# GarageAdminToken Tests
# ============================================================================

test_admin_token_resource() {
    log_test "Testing GarageAdminToken resource..."

    local timeout=30
    local end_time=$((SECONDS + timeout))
    while [ $SECONDS -lt $end_time ]; do
        local phase
        phase=$(kubectl get garageadmintoken garage-admin -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null)
        if [ "$phase" = "Ready" ]; then
            test_pass "GarageAdminToken is Ready"
            return 0
        fi
        sleep 2
    done
    test_fail "GarageAdminToken not ready (phase: $(kubectl get garageadmintoken garage-admin -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null))"
    return 1
}

# ============================================================================
# Error Handling Tests
# ============================================================================

test_invalid_cluster_reference() {
    log_test "Testing bucket with invalid cluster reference..."

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: invalid-cluster-bucket
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: nonexistent-cluster
  globalAlias: invalid-cluster-bucket
EOF

    local status=""
    local reference_deadline=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$reference_deadline" ]; do
        status=$(kubectl get garagebucket invalid-cluster-bucket -n "$NAMESPACE" \
            -o 'jsonpath={.status.phase}{"|"}{.status.conditions[?(@.type=="Ready")].status}{"|"}{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null)
        if [ "$status" = "Pending|False|ClusterNotReady" ]; then
            test_pass "Invalid cluster reference reports Pending with Ready=False/ClusterNotReady"
            kubectl delete garagebucket invalid-cluster-bucket -n "$NAMESPACE" \
                --wait=true --timeout=60s 2>/dev/null || true
            return 0
        fi
        sleep 3
    done
    test_fail "Invalid cluster reference did not report its waiting condition (status: ${status:-missing})"
    kubectl delete garagebucket invalid-cluster-bucket -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true
    return 1
}

test_invalid_bucket_reference() {
    log_test "Testing key with invalid bucket reference..."

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: invalid-bucket-key
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  name: invalid-bucket-key
  bucketPermissions:
    - bucketRef:
        name: nonexistent-bucket
      read: true
EOF

    local status=""
    local reference_deadline=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$reference_deadline" ]; do
        status=$(kubectl get garagekey invalid-bucket-key -n "$NAMESPACE" \
            -o 'jsonpath={.status.phase}{"|"}{.status.conditions[?(@.type=="Ready")].status}{"|"}{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null)
        if [ "$status" = "Failed|False|ReconcileFailed" ]; then
            test_pass "Invalid bucket reference reports Failed with Ready=False/ReconcileFailed"
            kubectl delete garagekey invalid-bucket-key -n "$NAMESPACE" \
                --wait=true --timeout=60s 2>/dev/null || true
            return 0
        fi
        sleep 3
    done
    test_fail "Invalid bucket reference did not report reconciliation failure (status: ${status:-missing})"
    kubectl delete garagekey invalid-bucket-key -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true
    return 1
}

test_key_import() {
    log_test "Testing key import with existing credentials..."

    # First create a key normally to get valid credentials
    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: source-key
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  name: source-key
  secretTemplate:
    name: source-credentials
EOF

    if ! check_resource_phase "garagekey" "source-key" "Ready" 60; then
        test_fail "Could not create source key for import test"
        kubectl delete garagekey source-key -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        return 1
    fi

    # Get the credentials from the first key
    local access_key
    access_key=$(kubectl get secret source-credentials -n "$NAMESPACE" -o jsonpath='{.data.access-key-id}' 2>/dev/null | base64 -d)
    local secret_key
    secret_key=$(kubectl get secret source-credentials -n "$NAMESPACE" -o jsonpath='{.data.secret-access-key}' 2>/dev/null | base64 -d)

    if [ -z "$access_key" ] || [ -z "$secret_key" ]; then
        test_fail "Could not get credentials from source key"
        kubectl delete garagekey source-key -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        return 1
    fi

    # Create an import secret
    kubectl create secret generic import-credentials -n "$NAMESPACE" \
        --from-literal=access-key-id="$access_key" \
        --from-literal=secret-access-key="$secret_key" 2>/dev/null || true

    # Try to import using the existing credentials
    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: imported-key
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  name: imported-key
  importKey:
    secretRef:
      name: import-credentials
      namespace: $NAMESPACE
  secretTemplate:
    name: imported-credentials
EOF

    local phase=""
    local imported_access=""
    local import_deadline=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$import_deadline" ]; do
        phase=$(kubectl get garagekey imported-key -n "$NAMESPACE" \
            -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
        imported_access=$(kubectl get garagekey imported-key -n "$NAMESPACE" \
            -o jsonpath='{.status.accessKeyId}' 2>/dev/null)
        if [ "$phase" = "Ready" ] && [ "$imported_access" = "$access_key" ]; then
            test_pass "Key import succeeded with the exact source accessKeyId"
            kubectl delete garagekey imported-key source-key -n "$NAMESPACE" \
                --wait=true --timeout=60s 2>/dev/null || true
            kubectl delete secret import-credentials -n "$NAMESPACE" \
                --wait=true --timeout=60s 2>/dev/null || true
            return 0
        fi
        sleep 3
    done

    test_fail "Key import did not converge to the source accessKeyId (phase: $phase, observed: ${imported_access:-missing})"
    kubectl delete garagekey imported-key source-key -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true
    kubectl delete secret import-credentials -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true
    return 1
}

test_invalid_zone_config() {
    log_test "Testing cluster with zone specified..."

    # Create a cluster with explicit zone
    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: zone-test-bucket
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  globalAlias: zone-test-bucket
EOF

    local matching_nodes=0
    local total_nodes=0
    local zone_deadline=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$zone_deadline" ]; do
        local nodes
        nodes=$(kubectl get garagenode -n "$NAMESPACE" \
            -l 'garage.rajsingh.info/cluster=garage,garage.rajsingh.info/tier=storage' \
            -o json 2>/dev/null || true)
        total_nodes=$(echo "$nodes" | jq -r '.items | length' 2>/dev/null || echo "0")
        matching_nodes=$(echo "$nodes" | jq -r '[.items[] | select(.spec.zone == "default" and .status.zone == "default" and .status.phase == "Ready")] | length' 2>/dev/null || echo "0")
        if [ "$total_nodes" = "3" ] && [ "$matching_nodes" = "3" ] && \
            check_resource_phase "garagebucket" "zone-test-bucket" "Ready" 2; then
            test_pass "All three storage nodes report the expected default zone"
            kubectl delete garagebucket zone-test-bucket -n "$NAMESPACE" \
                --wait=true --timeout=60s 2>/dev/null || true
            return 0
        fi
        sleep 3
    done
    test_fail "Default zone did not converge on every storage node (matching: $matching_nodes/$total_nodes)"
    kubectl delete garagebucket zone-test-bucket -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true
    return 1
}

test_replication_factor_validation() {
    log_test "Testing replication factor in cluster status..."

    local rep_factor=""
    local storage_nodes=""
    local factor_deadline=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$factor_deadline" ]; do
        rep_factor=$(kubectl get garagecluster garage -n "$NAMESPACE" \
            -o jsonpath='{.spec.replication.factor}' 2>/dev/null)
        storage_nodes=$(kubectl get garagecluster garage -n "$NAMESPACE" \
            -o jsonpath='{.status.health.storageNodes}' 2>/dev/null)
        if [ "$rep_factor" = "3" ] && [ "$storage_nodes" = "3" ]; then
            test_pass "Replication factor valid (factor: $rep_factor, nodes: $storage_nodes)"
            return 0
        fi
        sleep 3
    done

    test_fail "Replication factor not satisfied (factor: ${rep_factor:-missing}, nodes: ${storage_nodes:-missing})"
    return 1
}

# ============================================================================
# Finalizer Tests
# ============================================================================

test_finalizers_present() {
    log_test "Testing finalizers are present on resources..."

    finalizer_present() {
        local resource=$1
        local name=$2
        local expected=$3
        kubectl get "$resource" "$name" -n "$NAMESPACE" -o json 2>/dev/null |
            jq -e --arg expected "$expected" \
                '(.metadata.finalizers // []) | index($expected) != null' >/dev/null
    }

    if finalizer_present garagecluster garage "garagecluster.garage.rajsingh.info/finalizer" && \
        finalizer_present garagebucket test-bucket "garagebucket.garage.rajsingh.info/finalizer" && \
        finalizer_present garagekey test-key "garagekey.garage.rajsingh.info/finalizer"; then
        test_pass "Exact operator finalizers present on all resources"
        return 0
    fi
    test_fail "Missing one or more expected operator finalizers"
    return 1
}

# ============================================================================
# PVC Tests
# ============================================================================

test_pvc_creation() {
    log_test "Testing PVCs are created for StatefulSet..."

    local pvc_count
    pvc_count=$(kubectl get pvc -n "$NAMESPACE" -l "garage.rajsingh.info/cluster=garage" --no-headers 2>/dev/null | wc -l | tr -d ' ')

    if [ "$pvc_count" -ge "3" ]; then
        test_pass "PVCs created for all pods (count: $pvc_count)"
        return 0
    fi
    test_fail "Not enough PVCs (count: $pvc_count, expected: 3)"
    return 1
}

# ============================================================================
# Operator Resilience Tests
# ============================================================================

test_operator_restart() {
    log_test "Testing operator restart resilience..."

    # Deployment readiness and webhook endpoint readiness do not prove that a
    # newly elected manager has started its controller workers. Capture a
    # status field that the GarageNode reconciler refreshes on every connected
    # observation, then require the replacement manager to advance it before
    # creating resources for the next test section.
    local probe_node="garage-storage-0"
    local before_last_seen
    before_last_seen=$(kubectl get garagenode "$probe_node" -n "$NAMESPACE" -o jsonpath='{.status.lastSeen}' 2>/dev/null || true)

    # Restart operator
    kubectl rollout restart deployment/garage-operator -n "$NAMESPACE"
    kubectl rollout status deployment/garage-operator -n "$NAMESPACE" --timeout=60s
    NAMESPACE="$NAMESPACE" "$ROOT_DIR/hack/wait-for-operator-webhook.sh" "kind-$CLUSTER_NAME"

    local controller_ready="false"
    local controller_deadline=$((SECONDS + 120))
    while [ $SECONDS -lt $controller_deadline ]; do
        local after_last_seen
        after_last_seen=$(kubectl get garagenode "$probe_node" -n "$NAMESPACE" -o jsonpath='{.status.lastSeen}' 2>/dev/null || true)
        if [ -n "$after_last_seen" ] && [ "$after_last_seen" != "$before_last_seen" ]; then
            log_info "GarageNode controller observed $probe_node after restart"
            controller_ready="true"
            break
        fi
        sleep 2
    done
    if [ "$controller_ready" != "true" ]; then
        test_fail "GarageNode controller did not reconcile $probe_node after operator restart"
        return 1
    fi

    # Wait for cluster to become healthy (operator reconciles after restart)
    # This may take longer if the cluster was recovering from a previous test
    if wait_for_cluster_fully_ready 300; then
        test_pass "Cluster healthy after operator restart"
        return 0
    fi

    local connected
    connected=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.health.connectedNodes}' 2>/dev/null || echo "0")
    local health
    health=$(get_cluster_health)
    test_fail "Cluster unhealthy after operator restart (health: $health, connected: $connected/3)"
    return 1
}

# ============================================================================
# Secret Management Tests
# ============================================================================

test_secret_ownership() {
    log_test "Testing secret has correct owner reference..."

    # Wait for key to be Ready first (secret is only created when key is ready)
    if ! check_resource_phase "garagekey" "test-key" "Ready" 60; then
        test_fail "Secret owner reference - key not Ready"
        return 1
    fi

    local owner
    owner=$(kubectl get secret test-s3-credentials -n "$NAMESPACE" \
        -o jsonpath='{.metadata.ownerReferences[?(@.controller==true)].kind}' 2>/dev/null)
    if [ "$owner" = "GarageKey" ]; then
        test_pass "Secret has correct owner reference (GarageKey)"
        return 0
    fi
    test_fail "Secret owner reference incorrect (owner: $owner)"
    return 1
}

test_key_without_secret() {
    log_test "Testing key without secret template..."

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: no-secret-key
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  name: no-secret-template-key
EOF

    if check_resource_phase "garagekey" "no-secret-key" "Ready" 30; then
        # Verify no secret was created
        if ! kubectl get secret no-secret-key-credentials -n "$NAMESPACE" 2>/dev/null; then
            test_pass "Key without secret template works correctly"
            kubectl delete garagekey no-secret-key -n "$NAMESPACE" \
                --wait=true --timeout=60s 2>/dev/null || true
            return 0
        fi
    fi
    test_fail "Key without secret template failed"
    kubectl delete garagekey no-secret-key -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true
    return 1
}

# ============================================================================
# Conditions Tests
# ============================================================================

test_cluster_conditions() {
    log_test "Testing cluster conditions..."

    # Select by condition type — order in .status.conditions is not stable post-#190
    # (LegacySTSMigrated may sort before/after Ready depending on transition order).
    local ready_status
    ready_status=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)

    if [ "$ready_status" = "True" ]; then
        test_pass "Cluster conditions set correctly (Ready=True)"
        return 0
    fi
    test_fail "Cluster Ready condition not True (got: $ready_status)"
    return 1
}

# ============================================================================
# Idempotency Tests
# ============================================================================

test_idempotent_apply() {
    log_test "Testing idempotent resource apply..."

    # Establish a known-good source state before testing the no-op apply.
    if ! wait_for_cluster_fully_ready 60; then
        test_fail "Cluster was not fully ready before idempotent apply"
        return 1
    fi

    # Apply same resources again
    if ! kubectl apply -f hack/test-resources.yaml 2>/dev/null; then
        test_fail "Re-applying the unchanged resources failed"
        return 1
    fi

    # Require the full topology and partition evidence after re-apply.
    if wait_for_cluster_fully_ready 60; then
        test_pass "Resources are idempotent (re-apply works)"
        return 0
    fi
    test_fail "Idempotency test failed"
    return 1
}

# ============================================================================
# Concurrent Operations Test
# ============================================================================

test_concurrent_bucket_creation() {
    log_test "Testing concurrent bucket creation..."

    # Create multiple buckets at once
    for i in 1 2 3; do
        cat <<EOF | kubectl apply -f - &
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: concurrent-bucket-$i
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  globalAlias: concurrent-bucket-$i
EOF
    done
    wait

    # Check all buckets are ready
    local ready_count=0
    for i in 1 2 3; do
        if check_resource_phase "garagebucket" "concurrent-bucket-$i" "Ready" 60 2>/dev/null; then
            ((ready_count++))
        fi
    done

    # Cleanup
    for i in 1 2 3; do
        kubectl delete garagebucket "concurrent-bucket-$i" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
    done

    if [ "$ready_count" -ge "3" ]; then
        test_pass "Concurrent bucket creation succeeded ($ready_count/3)"
        return 0
    fi
    test_fail "Concurrent bucket creation failed ($ready_count/3 ready)"
    return 1
}

# ============================================================================
# Website Hosting Tests
# ============================================================================

test_website_bucket() {
    log_test "Testing bucket with website hosting..."

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: website-bucket
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  globalAlias: website-bucket
  website:
    enabled: true
    indexDocument: index.html
    errorDocument: error.html
EOF

    if check_resource_phase "garagebucket" "website-bucket" "Ready" 60; then
        # Verify website is enabled in status
        local website_enabled
        website_enabled=$(kubectl get garagebucket website-bucket -n "$NAMESPACE" -o jsonpath='{.status.websiteEnabled}' 2>/dev/null)
        if [ "$website_enabled" = "true" ]; then
            test_pass "Website bucket created with hosting enabled"
            kubectl delete garagebucket website-bucket -n "$NAMESPACE" \
                --wait=true --timeout=60s 2>/dev/null || true
            return 0
        fi
    fi
    test_fail "Website bucket creation failed"
    kubectl delete garagebucket website-bucket -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true
    return 1
}

test_webapi_endpoint() {
    log_test "Testing Web API endpoint serves website content..."

    local web_cluster="webapi-test-cluster"
    local web_bucket="webapi-test-site"
    local web_key="webapi-test-key"
    local web_root_domain=".web.garage.local"

    # Create RPC secret for the web cluster
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: ${web_cluster}-rpc-secret
  namespace: $NAMESPACE
type: Opaque
data:
  rpc-secret: YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OQ==
EOF

    # Create admin token
    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageAdminToken
metadata:
  name: ${web_cluster}-admin
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: $web_cluster
EOF

    # Create a single-node cluster with WebAPI enabled
    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: $web_cluster
  namespace: $NAMESPACE
spec:
  image: dxflrs/garage:v2.2.0@sha256:45a61ce3f7c9c24fc23d9ed2b09b27ed560ab87b34605d175d5c588f539c24e4
  zone: test-zone
  replication:
    factor: 1
  storage:
    replicas: 1
    metadata:
      size: 1Gi
    data:
      size: 5Gi
    resources:
      requests:
        memory: "256Mi"
        cpu: "100m"
  network:
    rpcBindPort: 3901
    rpcSecretRef:
      name: ${web_cluster}-rpc-secret
      key: rpc-secret
  s3Api:
    bindPort: 3900
    region: garage
  webApi:
    bindPort: 3902
    rootDomain: "$web_root_domain"
  admin:
    bindPort: 3903
    adminTokenSecretRef:
      name: ${web_cluster}-admin
      key: admin-token
EOF

    # Wait for cluster to be ready (GarageCluster uses "Running" phase, not "Ready")
    if ! check_resource_phase "garagecluster" "$web_cluster" "Running" 180; then
        test_fail "Web API test cluster did not become ready"
        kubectl delete garagecluster "$web_cluster" -n "$NAMESPACE" \
            --wait=false --request-timeout=15s 2>/dev/null || true
        kubectl delete garageadmintoken "${web_cluster}-admin" -n "$NAMESPACE" \
            --wait=false --request-timeout=15s 2>/dev/null || true
        kubectl delete secret "${web_cluster}-rpc-secret" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        return 1
    fi

    # Create bucket with website hosting
    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: $web_bucket
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: $web_cluster
  globalAlias: $web_bucket
  website:
    enabled: true
    indexDocument: index.html
    errorDocument: error.html
EOF

    # Create key with permissions
    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: $web_key
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: $web_cluster
  bucketPermissions:
    - bucketRef:
        name: $web_bucket
      read: true
      write: true
      owner: true
  secretTemplate:
    name: $web_key
    includeEndpoint: true
    includeRegion: true
EOF

    # Wait for bucket and key to be ready
    if ! check_resource_phase "garagebucket" "$web_bucket" "Ready" 60; then
        test_fail "Web API test bucket did not become ready"
        kubectl delete garagebucket "$web_bucket" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        kubectl delete garagekey "$web_key" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        kubectl delete garagecluster "$web_cluster" -n "$NAMESPACE" \
            --wait=false --request-timeout=15s 2>/dev/null || true
        kubectl delete garageadmintoken "${web_cluster}-admin" -n "$NAMESPACE" \
            --wait=false --request-timeout=15s 2>/dev/null || true
        kubectl delete secret "${web_cluster}-rpc-secret" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        return 1
    fi

    if ! check_resource_phase "garagekey" "$web_key" "Ready" 60; then
        test_fail "Web API test key did not become ready"
        kubectl delete garagebucket "$web_bucket" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        kubectl delete garagekey "$web_key" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        kubectl delete garagecluster "$web_cluster" -n "$NAMESPACE" \
            --wait=false --request-timeout=15s 2>/dev/null || true
        kubectl delete garageadmintoken "${web_cluster}-admin" -n "$NAMESPACE" \
            --wait=false --request-timeout=15s 2>/dev/null || true
        kubectl delete secret "${web_cluster}-rpc-secret" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        return 1
    fi

    # Get S3 credentials (default key names are access-key-id and secret-access-key)
    local access_key
    access_key=$(kubectl get secret "$web_key" -n "$NAMESPACE" -o jsonpath='{.data.access-key-id}' 2>/dev/null | base64 -d)
    local secret_key
    secret_key=$(kubectl get secret "$web_key" -n "$NAMESPACE" -o jsonpath='{.data.secret-access-key}' 2>/dev/null | base64 -d)

    if [ -z "$access_key" ] || [ -z "$secret_key" ]; then
        test_fail "Could not retrieve S3 credentials for Web API test"
        kubectl delete garagebucket "$web_bucket" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        kubectl delete garagekey "$web_key" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        kubectl delete garagecluster "$web_cluster" -n "$NAMESPACE" \
            --wait=false --request-timeout=15s 2>/dev/null || true
        kubectl delete garageadmintoken "${web_cluster}-admin" -n "$NAMESPACE" \
            --wait=false --request-timeout=15s 2>/dev/null || true
        kubectl delete secret "${web_cluster}-rpc-secret" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        return 1
    fi

    # Upload index.html using a job
    local index_content="<html><body><h1>Hello from Garage Web API!</h1></body></html>"
    local index_content_b64
    index_content_b64=$(echo -n "$index_content" | base64 -w0)

    cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: webapi-upload-index
  namespace: $NAMESPACE
spec:
  ttlSecondsAfterFinished: 300
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: upload
        image: amazon/aws-cli:2.27.41@sha256:bc6b7bba44ce38f9604ede49c584824af919047ea03fbcc7c7610671fdef95d8
        env:
        - name: AWS_ACCESS_KEY_ID
          value: "$access_key"
        - name: AWS_SECRET_ACCESS_KEY
          value: "$secret_key"
        - name: AWS_DEFAULT_REGION
          value: "garage"
        command:
        - /bin/sh
        - -c
        - |
          echo "$index_content_b64" | base64 -d > /tmp/index.html
          aws --endpoint-url http://${web_cluster}.${NAMESPACE}.svc.cluster.local:3900 \
            s3 cp /tmp/index.html s3://${web_bucket}/index.html \
            --content-type "text/html"
        securityContext:
          readOnlyRootFilesystem: false
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
EOF

    # Wait for upload job to complete. Do not continue to the HTTP assertion
    # when the job merely remains Pending/Running: that turns a scheduling or
    # network timeout into a misleading empty-response failure.
    local upload_succeeded=false
    local end_time=$((SECONDS + 120))
    while [ $SECONDS -lt $end_time ]; do
        local job_status
        job_status=$(kubectl get job webapi-upload-index -n "$NAMESPACE" \
            -o jsonpath='{.status.succeeded}' --request-timeout=5s 2>/dev/null || true)
        if [ "$job_status" = "1" ]; then
            log_info "Index upload succeeded"
            upload_succeeded=true
            break
        fi
        local job_failed
        job_failed=$(kubectl get job webapi-upload-index -n "$NAMESPACE" \
            -o jsonpath='{.status.failed}' --request-timeout=5s 2>/dev/null || true)
        if [[ "${job_failed:-0}" =~ ^[1-9][0-9]*$ ]]; then
            log_error "Index upload failed"
            kubectl logs job/webapi-upload-index -n "$NAMESPACE" 2>/dev/null || true
            test_fail "Web API index upload failed"
            kubectl delete job webapi-upload-index -n "$NAMESPACE" \
                --wait=true --timeout=60s 2>/dev/null || true
            kubectl delete garagebucket "$web_bucket" -n "$NAMESPACE" \
                --wait=true --timeout=60s 2>/dev/null || true
            kubectl delete garagekey "$web_key" -n "$NAMESPACE" \
                --wait=true --timeout=60s 2>/dev/null || true
            kubectl delete garagecluster "$web_cluster" -n "$NAMESPACE" \
                --wait=false --request-timeout=15s 2>/dev/null || true
            kubectl delete garageadmintoken "${web_cluster}-admin" -n "$NAMESPACE" \
                --wait=false --request-timeout=15s 2>/dev/null || true
            kubectl delete secret "${web_cluster}-rpc-secret" -n "$NAMESPACE" \
                --wait=true --timeout=60s 2>/dev/null || true
            return 1
        fi
        sleep 5
    done

    if [ "$upload_succeeded" != true ]; then
        log_error "Index upload did not complete before the 120s deadline"
        kubectl describe job webapi-upload-index -n "$NAMESPACE" 2>/dev/null || true
        kubectl logs job/webapi-upload-index -n "$NAMESPACE" 2>/dev/null || true
        test_fail "Web API index upload timed out"
        kubectl delete job webapi-upload-index -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        kubectl delete garagebucket "$web_bucket" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        kubectl delete garagekey "$web_key" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        kubectl delete garagecluster "$web_cluster" -n "$NAMESPACE" \
            --wait=false --request-timeout=15s 2>/dev/null || true
        kubectl delete garageadmintoken "${web_cluster}-admin" -n "$NAMESPACE" \
            --wait=false --request-timeout=15s 2>/dev/null || true
        kubectl delete secret "${web_cluster}-rpc-secret" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        return 1
    fi

    # Test accessing the website via Web API
    # The Host header should be: <bucket>.<rootDomain> (without leading dot)
    # web_root_domain has leading dot (e.g., ".web.garage.local")
    # We need: <bucket>.<rootDomain without leading dot> = webapi-test-site.web.garage.local
    local web_host="${web_bucket}.${web_root_domain#.}"
    local web_service_url="http://${web_cluster}.${NAMESPACE}.svc.cluster.local:3902/"

    # Create a pod to curl the web endpoint
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: webapi-curl-test
  namespace: $NAMESPACE
spec:
  restartPolicy: Never
  containers:
  - name: curl
    image: curlimages/curl:8.14.1@sha256:9a1ed35addb45476afa911696297f8e115993df459278ed036182dd2cd22b67b
    command:
    - curl
    - -s
    - -H
    - "Host: $web_host"
    - "$web_service_url"
    securityContext:
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000
EOF

    # Wait for curl pod to complete. A timeout is a test failure, not a signal
    # to read logs from a Pod that may not have run yet.
    local curl_succeeded=false
    end_time=$((SECONDS + 60))
    while [ $SECONDS -lt $end_time ]; do
        local pod_phase
        pod_phase=$(kubectl get pod webapi-curl-test -n "$NAMESPACE" \
            -o jsonpath='{.status.phase}' --request-timeout=5s 2>/dev/null || true)
        if [ "$pod_phase" = "Succeeded" ]; then
            curl_succeeded=true
            break
        fi
        if [ "$pod_phase" = "Failed" ]; then
            log_error "Curl pod failed"
            kubectl logs webapi-curl-test -n "$NAMESPACE" 2>/dev/null || true
            test_fail "Web API curl request failed"
            kubectl delete pod webapi-curl-test -n "$NAMESPACE" \
                --wait=true --timeout=60s 2>/dev/null || true
            kubectl delete job webapi-upload-index -n "$NAMESPACE" \
                --wait=true --timeout=60s 2>/dev/null || true
            kubectl delete garagebucket "$web_bucket" -n "$NAMESPACE" \
                --wait=true --timeout=60s 2>/dev/null || true
            kubectl delete garagekey "$web_key" -n "$NAMESPACE" \
                --wait=true --timeout=60s 2>/dev/null || true
            kubectl delete garagecluster "$web_cluster" -n "$NAMESPACE" \
                --wait=false --request-timeout=15s 2>/dev/null || true
            kubectl delete garageadmintoken "${web_cluster}-admin" -n "$NAMESPACE" \
                --wait=false --request-timeout=15s 2>/dev/null || true
            kubectl delete secret "${web_cluster}-rpc-secret" -n "$NAMESPACE" \
                --wait=true --timeout=60s 2>/dev/null || true
            return 1
        fi
        sleep 2
    done

    if [ "$curl_succeeded" != true ]; then
        log_error "Curl Pod did not complete before the 60s deadline (phase: ${pod_phase:-unknown})"
        kubectl describe pod webapi-curl-test -n "$NAMESPACE" 2>/dev/null || true
        kubectl logs webapi-curl-test -n "$NAMESPACE" 2>/dev/null || true
        test_fail "Web API curl request timed out"
        kubectl delete pod webapi-curl-test -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        kubectl delete job webapi-upload-index -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        kubectl delete garagebucket "$web_bucket" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        kubectl delete garagekey "$web_key" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        kubectl delete garagecluster "$web_cluster" -n "$NAMESPACE" \
            --wait=false --request-timeout=15s 2>/dev/null || true
        kubectl delete garageadmintoken "${web_cluster}-admin" -n "$NAMESPACE" \
            --wait=false --request-timeout=15s 2>/dev/null || true
        kubectl delete secret "${web_cluster}-rpc-secret" -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        return 1
    fi

    # Get the response
    local response
    response=$(kubectl logs webapi-curl-test -n "$NAMESPACE" 2>/dev/null)

    # Clean up - must delete objects from bucket before deleting bucket
    kubectl delete pod webapi-curl-test -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true
    kubectl delete job webapi-upload-index -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true

    # Delete objects from bucket using S3 API before deleting bucket
    cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: webapi-cleanup
  namespace: $NAMESPACE
spec:
  ttlSecondsAfterFinished: 60
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: cleanup
        image: amazon/aws-cli:2.27.41@sha256:bc6b7bba44ce38f9604ede49c584824af919047ea03fbcc7c7610671fdef95d8
        env:
        - name: AWS_ACCESS_KEY_ID
          value: "$access_key"
        - name: AWS_SECRET_ACCESS_KEY
          value: "$secret_key"
        - name: AWS_DEFAULT_REGION
          value: "garage"
        command:
        - /bin/sh
        - -c
        - |
          aws --endpoint-url http://${web_cluster}.${NAMESPACE}.svc.cluster.local:3900 \
            s3 rm s3://${web_bucket}/ --recursive
        securityContext:
          readOnlyRootFilesystem: false
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
EOF

    # Wait for cleanup job to complete before deleting the bucket. Leaving the
    # object behind can make the following bucket deletion race the cleanup
    # request and strand this fixture in a terminating state.
    local cleanup_succeeded=false cleanup_failed=false cleanup_end=$((SECONDS + 120))
    while [ $SECONDS -lt $cleanup_end ]; do
        local cleanup_status
        cleanup_status=$(kubectl get job webapi-cleanup -n "$NAMESPACE" \
            -o jsonpath='{.status.succeeded}' --request-timeout=5s 2>/dev/null || true)
        if [ "$cleanup_status" = "1" ]; then
            cleanup_succeeded=true
            break
        fi
        local cleanup_failures
        cleanup_failures=$(kubectl get job webapi-cleanup -n "$NAMESPACE" \
            -o jsonpath='{.status.failed}' --request-timeout=5s 2>/dev/null || true)
        if [[ "${cleanup_failures:-0}" =~ ^[1-9][0-9]*$ ]]; then
            cleanup_failed=true
            break
        fi
        sleep 2
    done
    if [ "$cleanup_succeeded" != true ]; then
        if [ "$cleanup_failed" = true ]; then
            log_error "Web API object cleanup job failed"
        else
            log_error "Web API object cleanup job did not complete before the 120s deadline"
        fi
        kubectl describe job webapi-cleanup -n "$NAMESPACE" 2>/dev/null || true
        kubectl logs job/webapi-cleanup -n "$NAMESPACE" 2>/dev/null || true
    fi
    kubectl delete job webapi-cleanup -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true

    # Now delete the bucket and other resources (use --wait=false to avoid blocking on finalizers)
    kubectl delete garagebucket "$web_bucket" -n "$NAMESPACE" \
        --wait=false --request-timeout=15s 2>/dev/null || true
    kubectl delete garagekey "$web_key" -n "$NAMESPACE" \
        --wait=false --request-timeout=15s 2>/dev/null || true
    kubectl delete garagecluster "$web_cluster" -n "$NAMESPACE" \
        --wait=false --request-timeout=15s 2>/dev/null || true
    kubectl delete garageadmintoken "${web_cluster}-admin" -n "$NAMESPACE" \
        --wait=false --request-timeout=15s 2>/dev/null || true
    kubectl delete secret "${web_cluster}-rpc-secret" -n "$NAMESPACE" \
        --wait=false --request-timeout=15s 2>/dev/null || true

    if [ "$cleanup_succeeded" != true ]; then
        test_fail "Web API object cleanup did not complete"
        return 1
    fi

    # Verify the response contains our content
    if echo "$response" | grep -q "Hello from Garage Web API!"; then
        test_pass "Web API endpoint correctly serves website content"
        return 0
    fi

    log_error "Expected 'Hello from Garage Web API!' in response, got: $response"
    test_fail "Web API endpoint did not serve expected content"
    return 1
}

# ============================================================================
# S3 Operations Tests (using curl for basic operations)
# ============================================================================

test_s3_list_buckets() {
    log_test "Testing S3 list buckets operation..."

    # Wait for key to be Ready first (secret is only created when key is ready)
    if ! check_resource_phase "garagekey" "test-key" "Ready" 60; then
        test_fail "S3 list buckets - key not Ready"
        return 1
    fi

    # Get credentials from secret
    local access_key
    access_key=$(kubectl get secret test-s3-credentials -n "$NAMESPACE" -o jsonpath='{.data.access-key-id}' 2>/dev/null | base64 -d)
    local secret_key
    secret_key=$(kubectl get secret test-s3-credentials -n "$NAMESPACE" -o jsonpath='{.data.secret-access-key}' 2>/dev/null | base64 -d)

    if [ -z "$access_key" ] || [ -z "$secret_key" ]; then
        test_fail "Could not retrieve S3 credentials"
        return 1
    fi

    # Exercise the named operation with a signed request from inside the cluster.
    kubectl delete job s3-list-buckets -n "$NAMESPACE" \
        --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1 || true
    cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: s3-list-buckets
  namespace: $NAMESPACE
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 300
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: aws-cli
        image: amazon/aws-cli:2.27.41@sha256:bc6b7bba44ce38f9604ede49c584824af919047ea03fbcc7c7610671fdef95d8
        env:
        - name: AWS_ACCESS_KEY_ID
          valueFrom:
            secretKeyRef:
              name: test-s3-credentials
              key: access-key-id
        - name: AWS_SECRET_ACCESS_KEY
          valueFrom:
            secretKeyRef:
              name: test-s3-credentials
              key: secret-access-key
        - name: AWS_DEFAULT_REGION
          value: garage
        - name: AWS_PAGER
          value: ""
        command:
        - aws
        - --endpoint-url
        - http://garage.${NAMESPACE}.svc.cluster.local:3900
        - s3api
        - list-buckets
        - --output
        - json
        securityContext:
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
EOF

    local job_succeeded=""
    local job_failed=""
    local job_deadline=$((SECONDS + 120))
    while [ "$SECONDS" -lt "$job_deadline" ]; do
        job_succeeded=$(kubectl get job s3-list-buckets -n "$NAMESPACE" \
            -o jsonpath='{.status.succeeded}' 2>/dev/null)
        job_failed=$(kubectl get job s3-list-buckets -n "$NAMESPACE" \
            -o jsonpath='{.status.failed}' 2>/dev/null)
        if [ "$job_succeeded" = "1" ] || [[ "${job_failed:-0}" =~ ^[1-9][0-9]*$ ]]; then
            break
        fi
        sleep 3
    done

    local response
    response=$(kubectl logs job/s3-list-buckets -n "$NAMESPACE" 2>/dev/null || true)
    kubectl delete job s3-list-buckets -n "$NAMESPACE" \
        --ignore-not-found --wait=false --request-timeout=15s >/dev/null 2>&1 || true

    if [ "$job_succeeded" = "1" ] && echo "$response" | \
        jq -e '.Buckets | any(.Name == "test-bucket")' >/dev/null 2>&1; then
        test_pass "Signed S3 ListBuckets returned test-bucket"
        return 0
    fi
    test_fail "Signed S3 ListBuckets did not return test-bucket (succeeded: ${job_succeeded:-0}, failed: ${job_failed:-0})"
    [ -n "$response" ] && log_error "ListBuckets response: $response"
    return 1
}

# ============================================================================
# GarageNode Tests
# ============================================================================

test_garagenode_creation() {
    log_test "Testing unreachable external GarageNode fails closed..."

    # This deliberately unreachable identity must never be published into the
    # shared Garage layout.
    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: custom-node
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  zone: custom-zone
  gateway: true
  nodeId: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  external:
    address: "192.168.1.100"
    port: 3901
EOF
    assert_external_garagenode_fails_closed custom-node \
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
        "Unreachable external GarageNode"
}

# ============================================================================
# Status Field Verification Tests
# ============================================================================

test_cluster_status_fields() {
    log_test "Testing cluster status fields are populated..."

    # Wait for cluster to be Running first
    if ! check_resource_phase "garagecluster" "garage" "Running" 60; then
        test_fail "Cluster status fields - cluster not Running"
        return 1
    fi

    local cluster_id
    cluster_id=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.clusterId}' 2>/dev/null)
    local layout_version
    layout_version=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.layoutVersion}' 2>/dev/null)
    local storage_nodes
    storage_nodes=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.health.storageNodes}' 2>/dev/null)

    if [ -n "$cluster_id" ] && [ -n "$layout_version" ] && [ "$storage_nodes" -gt "0" ] 2>/dev/null; then
        test_pass "Cluster status fields populated (clusterId: ${cluster_id:0:16}..., layoutVersion: $layout_version, storageNodes: $storage_nodes)"
        return 0
    fi
    test_fail "Cluster status fields missing (clusterId: $cluster_id, layoutVersion: $layout_version, storageNodes: $storage_nodes)"
    return 1
}

test_bucket_status_fields() {
    log_test "Testing bucket status fields are populated..."

    # Wait for bucket to be Ready first
    if ! check_resource_phase "garagebucket" "test-bucket" "Ready" 60; then
        test_fail "Bucket status fields - bucket not Ready"
        return 1
    fi

    local bucket_id
    bucket_id=$(kubectl get garagebucket test-bucket -n "$NAMESPACE" -o jsonpath='{.status.bucketId}' 2>/dev/null)
    local global_alias
    global_alias=$(kubectl get garagebucket test-bucket -n "$NAMESPACE" -o jsonpath='{.status.globalAlias}' 2>/dev/null)
    local size
    size=$(kubectl get garagebucket test-bucket -n "$NAMESPACE" -o jsonpath='{.status.size}' 2>/dev/null)
    if [ -n "$bucket_id" ] && [ "$global_alias" = "test-bucket" ] && [ -n "$size" ]; then
        test_pass "Bucket status fields populated (bucketId: ${bucket_id:0:16}..., alias: $global_alias, size: $size)"
        return 0
    fi
    test_fail "Bucket status fields missing or incorrect (bucketId: $bucket_id, alias: ${global_alias:-missing}, size: ${size:-missing})"
    return 1
}

test_key_status_fields() {
    log_test "Testing key status fields are populated..."

    # Wait for key to be Ready first
    if ! check_resource_phase "garagekey" "test-key" "Ready" 60; then
        test_fail "Key status fields - key not Ready"
        return 1
    fi

    local key_id
    key_id=$(kubectl get garagekey test-key -n "$NAMESPACE" -o jsonpath='{.status.keyId}' 2>/dev/null)
    local access_key_id
    access_key_id=$(kubectl get garagekey test-key -n "$NAMESPACE" -o jsonpath='{.status.accessKeyId}' 2>/dev/null)
    local secret_ref
    secret_ref=$(kubectl get garagekey test-key -n "$NAMESPACE" -o jsonpath='{.status.secretRef.name}' 2>/dev/null)

    if [ -n "$key_id" ] && [ -n "$access_key_id" ] && [ -n "$secret_ref" ]; then
        test_pass "Key status fields populated (keyId: ${key_id:0:16}..., accessKeyId: $access_key_id, secretRef: $secret_ref)"
        return 0
    fi
    test_fail "Key status fields missing (keyId: $key_id, accessKeyId: $access_key_id, secretRef: $secret_ref)"
    return 1
}

# ============================================================================
# Quota Enforcement Tests
# ============================================================================

test_quota_status_reporting() {
    log_test "Testing quota usage reporting..."

    local size_limit=""
    local object_limit=""
    local quota_deadline=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$quota_deadline" ]; do
        size_limit=$(kubectl get garagebucket quota-test-bucket -n "$NAMESPACE" \
            -o jsonpath='{.status.quotaUsage.sizeLimit}' 2>/dev/null)
        object_limit=$(kubectl get garagebucket quota-test-bucket -n "$NAMESPACE" \
            -o jsonpath='{.status.quotaUsage.objectLimit}' 2>/dev/null)
        if [ "$size_limit" = "524288000" ] && [ "$object_limit" = "500" ]; then
            test_pass "Quota usage reports configured limits (sizeLimit: $size_limit, objectLimit: $object_limit)"
            return 0
        fi
        sleep 3
    done

    test_fail "Quota usage did not report configured limits (sizeLimit: ${size_limit:-missing}, objectLimit: ${object_limit:-missing})"
    return 1
}

# ============================================================================
# Local Alias Tests
# ============================================================================

test_local_alias_creation() {
    log_test "Testing bucket with local alias..."

    local test_key_id
    test_key_id=$(kubectl get garagekey test-key -n "$NAMESPACE" \
        -o jsonpath='{.status.accessKeyId}' 2>/dev/null)
    if [ -z "$test_key_id" ]; then
        test_fail "Local alias prerequisite GarageKey/test-key has no accessKeyId"
        return 1
    fi

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: alias-test-bucket
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  globalAlias: alias-test-bucket
  localAliases:
    - keyRef: test-key
      alias: my-local-alias
EOF

    if check_resource_phase "garagebucket" "alias-test-bucket" "Ready" 60; then
        local alias_count=0
        local alias_bucket_id
        alias_bucket_id=$(kubectl get garagebucket alias-test-bucket -n "$NAMESPACE" \
            -o jsonpath='{.status.bucketId}' 2>/dev/null)
        local alias_deadline=$((SECONDS + 60))
        while [ "$SECONDS" -lt "$alias_deadline" ]; do
            # Garage v2.2 omits local-alias-only keys from GetBucketInfo unless
            # they also have bucket permissions. ListBuckets is the canonical
            # v2.2 API surface for the exact key-to-local-alias association.
            alias_count=$(garage_admin_get "/v2/ListBuckets" 2>/dev/null | \
                jq -r --arg bucket_id "$alias_bucket_id" --arg key_id "$test_key_id" \
                '[.[]? | select(.id == $bucket_id) | .localAliases[]? | select(.accessKeyId == $key_id and .alias == "my-local-alias")] | length' \
                2>/dev/null || echo "0")
            if [ "$alias_count" -ge 1 ] 2>/dev/null; then
                test_pass "Garage reports local alias my-local-alias for GarageKey/test-key's exact access key"
                kubectl delete garagebucket alias-test-bucket -n "$NAMESPACE" \
                    --wait=true --timeout=60s 2>/dev/null || true
                return 0
            fi
            sleep 3
        done
    fi
    test_fail "Garage did not report local alias my-local-alias for GarageKey/test-key's exact access key"
    kubectl delete garagebucket alias-test-bucket -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true
    return 1
}

# ============================================================================
# Observability Tests
# ============================================================================

test_observed_generation() {
    log_test "Testing observedGeneration tracking..."

    local cluster_gen
    cluster_gen=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.metadata.generation}' 2>/dev/null)
    local cluster_obs_gen
    cluster_obs_gen=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.observedGeneration}' 2>/dev/null)

    local bucket_gen
    bucket_gen=$(kubectl get garagebucket test-bucket -n "$NAMESPACE" -o jsonpath='{.metadata.generation}' 2>/dev/null)
    local bucket_obs_gen
    bucket_obs_gen=$(kubectl get garagebucket test-bucket -n "$NAMESPACE" -o jsonpath='{.status.observedGeneration}' 2>/dev/null)

    if [ "$cluster_gen" = "$cluster_obs_gen" ] && [ "$bucket_gen" = "$bucket_obs_gen" ]; then
        test_pass "ObservedGeneration tracking correct (cluster: $cluster_gen=$cluster_obs_gen, bucket: $bucket_gen=$bucket_obs_gen)"
        return 0
    fi
    test_fail "ObservedGeneration mismatch (cluster: $cluster_gen!=$cluster_obs_gen, bucket: $bucket_gen!=$bucket_obs_gen)"
    return 1
}

# ============================================================================
# Key Expiration Tests
# ============================================================================

test_key_expiration() {
    log_test "Testing key with expiration..."

    # Create a key with expiration set to 1 hour from now
    local expiration
    expiration=$(date -u -d "+1 hour" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -v+1H +"%Y-%m-%dT%H:%M:%SZ")

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: expiring-key
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  name: expiring-test-key
  expiresAt: "$expiration"
  secretTemplate:
    name: expiring-credentials
EOF

    if check_resource_phase "garagekey" "expiring-key" "Ready" 60; then
        local status_expiration=""
        local phase=""
        local expiration_deadline=$((SECONDS + 60))
        while [ "$SECONDS" -lt "$expiration_deadline" ]; do
            status_expiration=$(kubectl get garagekey expiring-key -n "$NAMESPACE" \
                -o jsonpath='{.status.expiresAt}' 2>/dev/null)
            phase=$(kubectl get garagekey expiring-key -n "$NAMESPACE" \
                -o jsonpath='{.status.phase}' 2>/dev/null)
            if [ "$status_expiration" = "$expiration" ] && [ "$phase" = "Ready" ]; then
                test_pass "Key expiration converged (expiresAt: $status_expiration, phase: $phase)"
                kubectl delete garagekey expiring-key -n "$NAMESPACE" \
                    --wait=true --timeout=60s 2>/dev/null || true
                return 0
            fi
            sleep 3
        done
    fi
    test_fail "Key expiration did not converge (expected: $expiration, observed: ${status_expiration:-missing}, phase: ${phase:-missing})"
    kubectl delete garagekey expiring-key -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true
    return 1
}

test_key_never_expires() {
    log_test "Testing key with neverExpires flag..."

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: permanent-key
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  name: permanent-test-key
  neverExpires: true
  secretTemplate:
    name: permanent-credentials
EOF

    if ! check_resource_phase "garagekey" "permanent-key" "Ready" 60; then
        test_fail "Key with neverExpires flag did not reach Ready"
        kubectl delete garagekey permanent-key -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        return 1
    fi

    local access_key_id
    access_key_id=$(kubectl get garagekey permanent-key -n "$NAMESPACE" \
        -o jsonpath='{.status.accessKeyId}' 2>/dev/null)
    local admin_token
    admin_token=$(kubectl get secret garage-admin-token -n "$NAMESPACE" \
        -o jsonpath='{.data.admin-token}' 2>/dev/null | base64 -d)
    if [ -z "$access_key_id" ] || [ -z "$admin_token" ]; then
        test_fail "Cannot verify neverExpires in Garage (accessKeyId or admin token missing)"
        kubectl delete garagekey permanent-key -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        return 1
    fi

    if ! start_port_forward svc/garage 3903 "$NAMESPACE" 30; then
        test_fail "Admin API port-forward did not start"
        return 1
    fi
    local pf_pid=$PORT_FORWARD_PID pf_port=$PORT_FORWARD_PORT pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:${pf_port}/health" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Admin API port-forward did not become ready"
        return 1
    fi
    local key_info=""
    local permanent=false
    local expiration_deadline=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$expiration_deadline" ]; do
        key_info=$(curl -fsS --connect-timeout 5 --max-time 10 --get \
            -H "Authorization: Bearer ${admin_token}" \
            --data-urlencode "id=${access_key_id}" \
            "http://127.0.0.1:${pf_port}/v2/GetKeyInfo" 2>/dev/null || true)
        if jq -e '.expiration == null and .expired == false' \
            <<< "$key_info" >/dev/null 2>&1; then
            permanent=true
            break
        fi
        sleep 3
    done
    stop_port_forward "$pf_pid" "$pf_log"

    kubectl delete garagekey permanent-key -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true
    if [ "$permanent" = true ]; then
        test_pass "Garage reports the permanent key as unexpired with no expiration"
        return 0
    fi
    test_fail "Garage did not report expiration=null and expired=false for the permanent key (response: ${key_info:-missing})"
    return 1
}

# ============================================================================
# Gateway Node Tests
# ============================================================================

test_gateway_node() {
    log_test "Testing unreachable external gateway GarageNode fails closed..."

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: gateway-node
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  zone: gateway-zone
  gateway: true
  nodeId: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
  external:
    address: "192.168.1.101"
    port: 3901
EOF
    assert_external_garagenode_fails_closed gateway-node \
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" \
        "Unreachable external gateway"
}

# ============================================================================
# Config Change Restart Tests
# ============================================================================

test_config_change_triggers_restart() {
    log_test "Testing config change triggers pod restart..."

    local new_hash
    new_hash=$(kubectl get statefulset garage-storage-0 -n "$NAMESPACE" \
        -o jsonpath='{.spec.template.metadata.annotations.garage\.rajsingh\.info/config-hash}' 2>/dev/null)
    local hash_changed=false
    if [ "$CONFIG_CHANGE_APPLIED" = true ] && [ -n "$CONFIG_CHANGE_INITIAL_HASH" ] && \
       [ -n "$new_hash" ] && [ "$CONFIG_CHANGE_INITIAL_HASH" != "$new_hash" ]; then
        hash_changed=true
    fi

    # Compression, logging, and region were deliberately applied in one
    # generation so the production OnDelete policy needs only one serialized
    # three-node rollout. Revert them together for the same reason.
    kubectl patch garagecluster garage -n "$NAMESPACE" --type=json \
        -p '[{"op":"remove","path":"/spec/blocks"},{"op":"remove","path":"/spec/logging"},{"op":"replace","path":"/spec/s3Api/region","value":"garage"}]' 2>/dev/null || true
    if ! wait_for_storage_rollout_converged garage 600; then
        test_fail "Combined config change revert did not converge"
        return 1
    fi
    if [ "$hash_changed" = true ]; then
        test_pass "Config change updated config-hash ($CONFIG_CHANGE_INITIAL_HASH -> $new_hash)"
        return 0
    fi
    test_fail "Converged config generation did not update the StatefulSet config hash"
    return 1
}

# ============================================================================
# PDB Tests
# ============================================================================

test_pdb_creation() {
    log_test "Testing PodDisruptionBudget creation..."

    if ! wait_for_storage_rollout_converged garage 600; then
        test_fail "PDB change: preceding storage generation did not converge"
        return 1
    fi

    # Enable PDB — pass minAvailable as integer (not quoted string; "2" would be
    # treated as a non-percentage string and rejected by the PDB API).
    # v1beta2 field path is spec.storage.podDisruptionBudget; the v0.5.x
    # spec.podDisruptionBudget path is a v1beta1-only artifact that the
    # conversion webhook lifts into spec.storage.
    kubectl patch garagecluster garage -n "$NAMESPACE" --type=merge \
        -p '{"spec":{"storage":{"podDisruptionBudget":{"enabled":true,"minAvailable":2}}}}'

    # Wait for PDB to be created (controller needs time to reconcile)
    local timeout=30
    local end_time=$((SECONDS + timeout))
    while [ $SECONDS -lt $end_time ]; do
        if kubectl get pdb garage -n "$NAMESPACE" &>/dev/null; then
            local min_available
            min_available=$(kubectl get pdb garage -n "$NAMESPACE" -o jsonpath='{.spec.minAvailable}' 2>/dev/null)
            if [ "$min_available" = "2" ]; then
                if ! wait_for_storage_rollout_converged garage 600; then
                    test_fail "PDB generation did not converge"
                    return 1
                fi
                test_pass "PDB created with minAvailable: $min_available"
                return 0
            fi
        fi
        sleep 2
    done

    test_fail "PDB did not converge with minAvailable=2"
    return 1
}

# ============================================================================
# Logging Configuration Tests
# ============================================================================

test_logging_config() {
    log_test "Testing logging configuration (RUST_LOG env var)..."

    local rust_log
    rust_log=$(kubectl get statefulset garage-storage-0 -n "$NAMESPACE" \
        -o 'jsonpath={.spec.template.spec.containers[?(@.name=="garage")].env[?(@.name=="RUST_LOG")].value}' 2>/dev/null)
    if [ "$CONFIG_CHANGE_APPLIED" = true ] && [ "$rust_log" = "debug" ]; then
        test_pass "Logging config applied (RUST_LOG=$rust_log)"
        return 0
    fi
    test_fail "Logging config not present in the converged combined config generation (RUST_LOG=${rust_log:-missing})"
    return 1
}

# ============================================================================
# Secret Template Customization Tests
# ============================================================================

test_secret_template_custom_keys() {
    log_test "Testing secret template with custom keys..."

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: custom-secret-key
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  name: custom-secret-test
  secretTemplate:
    name: custom-credentials
    accessKeyIdKey: AWS_ACCESS_KEY_ID
    secretAccessKeyKey: AWS_SECRET_ACCESS_KEY
    endpointKey: S3_ENDPOINT
    regionKey: AWS_REGION
    labels:
      custom-label: test-value
    annotations:
      custom-annotation: test-annotation
EOF

    if check_resource_phase "garagekey" "custom-secret-key" "Ready" 60; then
        local access_key=""
        local secret_key=""
        local endpoint=""
        local region=""
        local custom_label=""
        local custom_annotation=""
        local secret_deadline=$((SECONDS + 60))
        while [ "$SECONDS" -lt "$secret_deadline" ]; do
            access_key=$(kubectl get secret custom-credentials -n "$NAMESPACE" \
                -o jsonpath='{.data.AWS_ACCESS_KEY_ID}' 2>/dev/null)
            secret_key=$(kubectl get secret custom-credentials -n "$NAMESPACE" \
                -o jsonpath='{.data.AWS_SECRET_ACCESS_KEY}' 2>/dev/null)
            endpoint=$(kubectl get secret custom-credentials -n "$NAMESPACE" \
                -o jsonpath='{.data.S3_ENDPOINT}' 2>/dev/null)
            region=$(kubectl get secret custom-credentials -n "$NAMESPACE" \
                -o jsonpath='{.data.AWS_REGION}' 2>/dev/null)
            custom_label=$(kubectl get secret custom-credentials -n "$NAMESPACE" \
                -o jsonpath='{.metadata.labels.custom-label}' 2>/dev/null)
            custom_annotation=$(kubectl get secret custom-credentials -n "$NAMESPACE" \
                -o jsonpath='{.metadata.annotations.custom-annotation}' 2>/dev/null)

            if [ -n "$access_key" ] && [ -n "$secret_key" ] && [ -n "$endpoint" ] &&
                [ -n "$region" ] && [ "$custom_label" = "test-value" ] &&
                [ "$custom_annotation" = "test-annotation" ]; then
                test_pass "Secret template contains every custom key, label, and annotation"
                kubectl delete garagekey custom-secret-key -n "$NAMESPACE" \
                    --wait=true --timeout=60s 2>/dev/null || true
                return 0
            fi
            sleep 3
        done
    fi
    test_fail "Secret template did not converge with every custom key, label, and annotation"
    kubectl delete garagekey custom-secret-key -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true
    return 1
}

# ============================================================================
# Database Engine Tests
# ============================================================================

test_database_engine_config() {
    log_test "Testing database engine configuration in TOML..."

    # Read the exact immutable revision mounted by a current storage workload.
    local config
    config=$(get_primary_storage_config)

    if [ -z "$config" ]; then
        test_fail "Mounted Garage configuration is unavailable"
        return 1
    fi

    if echo "$config" | grep -q '^db_engine = "lmdb"$'; then
        local engine
        engine=$(echo "$config" | grep '^db_engine = ' | head -1)
        test_pass "Database engine configured: $engine"
        return 0
    fi

    if echo "$config" | grep -q '^db_engine = '; then
        local engine
        engine=$(echo "$config" | grep '^db_engine = ' | head -1)
        test_fail "Database engine does not match the expected lmdb default: $engine"
        return 1
    fi

    # Garage defaults an omitted db_engine to lmdb.
    test_pass "Database engine using default (lmdb)"
    return 0
}

# ============================================================================
# Block Compression Tests
# ============================================================================

test_compression_config() {
    log_test "Testing block compression configuration..."

    if ! wait_for_storage_rollout_converged garage 600; then
        test_fail "Compression change: preceding storage generation did not converge"
        return 1
    fi

    CONFIG_CHANGE_INITIAL_HASH=$(kubectl get statefulset garage-storage-0 -n "$NAMESPACE" \
        -o jsonpath='{.spec.template.metadata.annotations.garage\.rajsingh\.info/config-hash}' 2>/dev/null)
    if [ -z "$CONFIG_CHANGE_INITIAL_HASH" ]; then
        test_fail "Combined config change has no initial StatefulSet config hash"
        return 1
    fi

    # Exercise three config surfaces in one generation. This preserves broad
    # coverage without needlessly rolling every storage process six times.
    kubectl patch garagecluster garage -n "$NAMESPACE" --type=merge \
        -p '{"spec":{"blocks":{"compressionLevel":"none"},"logging":{"level":"debug"},"s3Api":{"region":"test-region-change"}}}'

    if ! wait_for_storage_rollout_converged garage 600; then
        test_fail "Combined compression/logging/region change did not converge"
        return 1
    fi
    CONFIG_CHANGE_APPLIED=true

    # Check the exact immutable revision mounted by the current workload.
    local config
    config=$(get_primary_storage_config)

    if echo "$config" | grep -q 'compression_level = "none"'; then
        test_pass "Compression level 'none' properly quoted in TOML"
        return 0
    fi
    local detail="compression_level missing from converged mounted config"
    if echo "$config" | grep -q "compression_level"; then
        detail=$(echo "$config" | grep "compression_level" | head -1)
    fi
    test_fail "Compression level was not published correctly: $detail"
    return 1
}

# ============================================================================
# Build Info Status Tests
# ============================================================================

test_build_info_status() {
    log_test "Testing build info in cluster status..."

    local version
    version=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.buildInfo.version}' 2>/dev/null)
    local rust_version
    rust_version=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.buildInfo.rustVersion}' 2>/dev/null)

    if [ -n "$version" ]; then
        test_pass "Build info populated (version: $version, rust: ${rust_version:-not-set})"
        return 0
    fi
    test_fail "Build info not populated in status"
    return 1
}

# ============================================================================
# Storage Stats Status Tests
# ============================================================================

test_storage_stats_status() {
    log_test "Testing storage stats in cluster status..."

    local total_capacity
    total_capacity=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.storageStats.totalCapacity}' 2>/dev/null)
    local used_capacity
    used_capacity=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.storageStats.usedCapacity}' 2>/dev/null)
    local available_capacity
    available_capacity=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.storageStats.availableCapacity}' 2>/dev/null)

    if [ -n "$total_capacity" ] && [ -n "$used_capacity" ] && [ -n "$available_capacity" ]; then
        test_pass "Storage stats populated (total: $total_capacity, used: $used_capacity, available: $available_capacity)"
        return 0
    fi

    test_fail "Storage stats not fully populated (total: ${total_capacity:-missing}, used: ${used_capacity:-missing}, available: ${available_capacity:-missing})"
    return 1
}

# ============================================================================
# Create Bucket Permission Tests
# ============================================================================

test_key_create_bucket_permission() {
    log_test "Testing key with createBucket permission..."

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: admin-key
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  name: admin-test-key
  permissions:
    createBucket: true
  secretTemplate:
    name: admin-credentials
EOF

    if check_resource_phase "garagekey" "admin-key" "Ready" 60; then
        local create_bucket=""
        local permission_deadline=$((SECONDS + 60))
        while [ "$SECONDS" -lt "$permission_deadline" ]; do
            create_bucket=$(kubectl get garagekey admin-key -n "$NAMESPACE" \
                -o jsonpath='{.status.permissions.createBucket}' 2>/dev/null)
            if [ "$create_bucket" = "true" ]; then
                test_pass "Key reports createBucket permission enabled"
                kubectl delete garagekey admin-key -n "$NAMESPACE" \
                    --wait=true --timeout=60s 2>/dev/null || true
                return 0
            fi
            sleep 3
        done
    fi
    test_fail "Key did not report createBucket permission enabled (observed: ${create_bucket:-missing})"
    kubectl delete garagekey admin-key -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true
    return 1
}

# ============================================================================
# Bucket Key Permissions Defined on Bucket Tests
# ============================================================================

test_bucket_key_permissions() {
    log_test "Testing bucket with keyPermissions defined on bucket..."

    local test_key_id
    test_key_id=$(kubectl get garagekey test-key -n "$NAMESPACE" \
        -o jsonpath='{.status.accessKeyId}' 2>/dev/null)
    if [ -z "$test_key_id" ]; then
        test_fail "Bucket permission prerequisite GarageKey/test-key has no accessKeyId"
        return 1
    fi

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: permissions-bucket
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  globalAlias: permissions-bucket
  keyPermissions:
    - keyRef:
        name: test-key
      read: true
      write: true
      owner: true
EOF

    if check_resource_phase "garagebucket" "permissions-bucket" "Ready" 60; then
        local matching_permissions=0
        local permissions_deadline=$((SECONDS + 60))
        while [ "$SECONDS" -lt "$permissions_deadline" ]; do
            matching_permissions=$(kubectl get garagebucket permissions-bucket -n "$NAMESPACE" -o json 2>/dev/null | \
                jq -r --arg key_id "$test_key_id" \
                '[.status.keys[]? | select(.keyId == $key_id and .permissions.read == true and .permissions.write == true and .permissions.owner == true)] | length' \
                2>/dev/null || echo "0")
            if [ "$matching_permissions" -ge 1 ] 2>/dev/null; then
                test_pass "Bucket reports read, write, and owner permissions for test-key"
                kubectl delete garagebucket permissions-bucket -n "$NAMESPACE" \
                    --wait=true --timeout=60s 2>/dev/null || true
                return 0
            fi
            sleep 3
        done
    fi
    test_fail "Bucket did not report read, write, and owner permissions for test-key"
    kubectl delete garagebucket permissions-bucket -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true
    return 1
}

# ============================================================================
# Incomplete Multipart Upload Status Tests
# ============================================================================

test_bucket_mpu_status() {
    log_test "Testing bucket incomplete uploads status..."

    if ! check_resource_phase "garagebucket" "test-bucket" "Ready" 60; then
        test_fail "Bucket incomplete uploads status unavailable because test-bucket is not Ready"
        return 1
    fi

    # The API omits the zero-valued field, so empty and literal zero both
    # affirmatively represent no incomplete uploads on a Ready bucket.
    local incomplete_uploads
    incomplete_uploads=$(kubectl get garagebucket test-bucket -n "$NAMESPACE" -o jsonpath='{.status.incompleteUploads}' 2>/dev/null)
    if [ -n "$incomplete_uploads" ] && [[ ! "$incomplete_uploads" =~ ^[0-9]+$ ]]; then
        test_fail "Bucket incomplete uploads status is not numeric (value: $incomplete_uploads)"
        return 1
    fi
    test_pass "Ready bucket reports incomplete uploads count ${incomplete_uploads:-0}"
    return 0
}

# ============================================================================
# Operational Annotation Tests
# ============================================================================

test_connect_nodes_annotation() {
    log_test "Testing connect-nodes annotation processing..."

    # Get a node ID and address with a bounded wait.
    local node_id=""
    local pod_ip=""
    local node_deadline=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$node_deadline" ]; do
        node_id=$(kubectl get garagenode garage-storage-0 -n "$NAMESPACE" \
            -o jsonpath='{.status.nodeId}' 2>/dev/null)
        pod_ip=$(pod_ip_for_selector "$NAMESPACE" \
            "garage.rajsingh.info/node=garage-storage-0" || true)
        [ -n "$node_id" ] && [ -n "$pod_ip" ] && break
        sleep 3
    done

    if [ -z "$node_id" ] || [ -z "$pod_ip" ]; then
        test_fail "connect-nodes prerequisites unavailable (nodeId: ${node_id:-missing}, podIP: ${pod_ip:-missing})"
        return 1
    fi

    # Apply the connect-nodes annotation (connecting to self is a no-op but tests the parsing)
    if ! kubectl annotate garagecluster garage -n "$NAMESPACE" \
        "garage.rajsingh.info/connect-nodes=${node_id}@${pod_ip}:3901" --overwrite; then
        test_fail "connect-nodes annotation could not be applied"
        return 1
    fi

    # The annotation should be removed after processing.
    local annotation=""
    local annotation_deadline=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$annotation_deadline" ]; do
        annotation=$(kubectl get garagecluster garage -n "$NAMESPACE" \
            -o jsonpath='{.metadata.annotations.garage\.rajsingh\.info/connect-nodes}' 2>/dev/null)
        if [ -z "$annotation" ]; then
            test_pass "connect-nodes annotation processed and removed"
            return 0
        fi
        sleep 3
    done

    test_fail "connect-nodes annotation not processed (still present: $annotation)"
    # Clean up
    kubectl annotate garagecluster garage -n "$NAMESPACE" "garage.rajsingh.info/connect-nodes-" 2>/dev/null || true
    return 1
}

test_pause_reconcile_annotation() {
    log_test "Testing pause-reconcile annotation..."

    # The annotation is intentionally unsupported. Maintenance suspension is
    # configured through spec.maintenance.suspended instead.
    test_skip "pause-reconcile annotation is unsupported; use spec.maintenance.suspended"
    return 0
}

test_force_layout_apply_annotation() {
    log_test "Testing force-layout-apply annotation..."

    # Apply force layout annotation
    kubectl annotate garagecluster garage -n "$NAMESPACE" \
        "garage.rajsingh.info/force-layout-apply=true" --overwrite

    # Unlike one-shot operational annotations, force-layout-apply is a
    # documented persistent bootstrap flag. Verify that exact contract.
    local annotation=""
    local annotation_deadline=$((SECONDS + 30))
    while [ "$SECONDS" -lt "$annotation_deadline" ]; do
        annotation=$(kubectl get garagecluster garage -n "$NAMESPACE" \
            -o jsonpath='{.metadata.annotations.garage\.rajsingh\.info/force-layout-apply}' 2>/dev/null)
        [ "$annotation" = "true" ] && break
        sleep 2
    done

    if ! kubectl annotate garagecluster garage -n "$NAMESPACE" \
        "garage.rajsingh.info/force-layout-apply-" >/dev/null 2>&1; then
        test_fail "force-layout-apply annotation could not be cleaned up"
        return 1
    fi

    if [ "$annotation" = "true" ]; then
        test_pass "force-layout-apply persisted as the documented bootstrap flag"
        return 0
    fi

    test_fail "force-layout-apply did not persist with value true"
    return 1
}

# ============================================================================
# Node Tags Tests
# ============================================================================

test_node_with_tags() {
    log_test "Testing unreachable tagged external GarageNode fails closed..."

    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: tagged-node
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: garage
  zone: tagged-zone
  gateway: true
  tags:
    - ssd
    - rack-a
    - tier-1
  nodeId: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
  external:
    address: "192.168.1.102"
    port: 3901
EOF
    assert_external_garagenode_fails_closed tagged-node \
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" \
        "Unreachable tagged external GarageNode"
}

# ============================================================================
# Metrics Endpoint Tests
# ============================================================================

test_metrics_endpoint() {
    log_test "Testing metrics endpoint accessibility..."

    if ! start_port_forward svc/garage 3903 "$NAMESPACE" 30; then
        test_fail "Admin API port-forward did not start"
        return 1
    fi
    local pf_pid=$PORT_FORWARD_PID pf_port=$PORT_FORWARD_PORT pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$pf_port/health" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Admin API port-forward did not become ready"
        return 1
    fi

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$pf_port/metrics" 2>/dev/null || echo "000")
    stop_port_forward "$pf_pid" "$pf_log"

    # 200 = success, 401/403 = auth required (also acceptable)
    if [ "$http_code" = "200" ] || [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
        test_pass "Metrics endpoint responding (HTTP $http_code)"
        return 0
    fi
    test_fail "Metrics endpoint not responding (HTTP $http_code)"
    return 1
}

# ============================================================================
# Health Endpoint Tests
# ============================================================================

test_health_endpoint() {
    log_test "Testing health endpoint..."

    if ! start_port_forward svc/garage 3903 "$NAMESPACE" 30; then
        test_fail "Admin API port-forward did not start"
        return 1
    fi
    local pf_pid=$PORT_FORWARD_PID pf_port=$PORT_FORWARD_PORT pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$pf_port/health" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        test_fail "Admin API port-forward did not become ready"
        return 1
    fi

    local response
    response=$(curl -s "http://127.0.0.1:$pf_port/health" 2>/dev/null)
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$pf_port/health" 2>/dev/null || echo "000")
    stop_port_forward "$pf_pid" "$pf_log"

    if [ "$http_code" = "200" ]; then
        test_pass "Health endpoint responding: $response"
        return 0
    fi
    test_fail "Health endpoint not responding (HTTP $http_code)"
    return 1
}

# ============================================================================
# Manual Mode with GarageNode Tests
# ============================================================================

test_manual_mode_cluster_creation() {
    log_test "Testing GarageCluster in Manual mode (no StatefulSet)..."

    # Create a Manual mode cluster
    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: manual-cluster
  namespace: $NAMESPACE
spec:
  layoutPolicy: Manual
  storage:
    metadata:
      size: 100Mi
    data:
      size: 1Gi
  replication:
    factor: 2
  admin:
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
EOF

    local phase=""
    local manual_deadline=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$manual_deadline" ]; do
        if kubectl get statefulset manual-cluster -n "$NAMESPACE" >/dev/null 2>&1; then
            test_fail "StatefulSet should NOT exist for Manual mode cluster"
            kubectl delete garagecluster manual-cluster -n "$NAMESPACE" \
                --wait=true --timeout=120s 2>/dev/null || true
            return 1
        fi
        phase=$(kubectl get garagecluster manual-cluster -n "$NAMESPACE" \
            -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
        if [ "$phase" = "Running" ] || [ "$phase" = "Pending" ]; then
            test_pass "Manual mode cluster reached $phase without creating a StatefulSet"
            return 0
        fi
        sleep 3
    done
    test_fail "Manual mode cluster did not reach Pending or Running without a StatefulSet (phase: $phase)"
    kubectl delete garagecluster manual-cluster -n "$NAMESPACE" \
        --wait=true --timeout=120s 2>/dev/null || true
    return 1
}

test_garagenode_statefulset_creation() {
    log_test "Testing GarageNode creates its own StatefulSet..."

    # Create GarageNode 1 for the manual cluster
    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: manual-node-1
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: manual-cluster
  zone: zone-a
  capacity: 1Gi
  storage:
    metadata:
      size: 100Mi
    data:
      size: 1Gi
EOF

    # Wait for StatefulSet to be created
    local timeout=60
    local end_time=$((SECONDS + timeout))
    while [ $SECONDS -lt $end_time ]; do
        if kubectl get statefulset manual-node-1 -n "$NAMESPACE" &>/dev/null; then
            test_pass "GarageNode created its own StatefulSet"
            break
        fi
        sleep 3
    done

    if ! kubectl get statefulset manual-node-1 -n "$NAMESPACE" &>/dev/null; then
        test_fail "GarageNode did not create StatefulSet"
        return 1
    fi

    # Wait for pod to be running
    if wait_for_pods_ready "garage.rajsingh.info/node=manual-node-1" 1 120; then
        test_pass "GarageNode pod is running"
    else
        test_fail "GarageNode pod did not become ready"
        return 1
    fi

    return 0
}

test_manual_mode_second_node() {
    log_test "Testing second GarageNode in Manual mode..."

    # Create GarageNode 2 for the manual cluster
    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageNode
metadata:
  name: manual-node-2
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: manual-cluster
  zone: zone-b
  capacity: 1Gi
  storage:
    metadata:
      size: 100Mi
    data:
      size: 1Gi
EOF

    # Wait for StatefulSet 2 to be created
    local timeout=60
    local end_time=$((SECONDS + timeout))
    while [ $SECONDS -lt $end_time ]; do
        if kubectl get statefulset manual-node-2 -n "$NAMESPACE" &>/dev/null; then
            test_pass "Second GarageNode created its own StatefulSet"
            break
        fi
        sleep 3
    done

    if ! kubectl get statefulset manual-node-2 -n "$NAMESPACE" &>/dev/null; then
        test_fail "Second GarageNode did not create StatefulSet"
        return 1
    fi

    # Wait for pod to be running
    if wait_for_pods_ready "garage.rajsingh.info/node=manual-node-2" 1 120; then
        test_pass "Second GarageNode pod is running"
    else
        test_fail "Second GarageNode pod did not become ready"
        return 1
    fi

    return 0
}

test_manual_mode_nodes_in_layout() {
    log_test "Testing Manual mode nodes registered in layout..."

    # Wait for nodes to be in layout
    local timeout=120
    local end_time=$((SECONDS + timeout))

    while [ $SECONDS -lt $end_time ]; do
        local node1_in_layout
        node1_in_layout=$(kubectl get garagenode manual-node-1 -n "$NAMESPACE" -o jsonpath='{.status.inLayout}' 2>/dev/null || echo "false")
        local node2_in_layout
        node2_in_layout=$(kubectl get garagenode manual-node-2 -n "$NAMESPACE" -o jsonpath='{.status.inLayout}' 2>/dev/null || echo "false")

        if [ "$node1_in_layout" = "true" ] && [ "$node2_in_layout" = "true" ]; then
            test_pass "Both nodes registered in layout"
            return 0
        fi
        sleep 5
    done

    local node1_status
    node1_status=$(kubectl get garagenode manual-node-1 -n "$NAMESPACE" -o jsonpath='{.status.inLayout}' 2>/dev/null)
    local node2_status
    node2_status=$(kubectl get garagenode manual-node-2 -n "$NAMESPACE" -o jsonpath='{.status.inLayout}' 2>/dev/null)
    test_fail "Nodes not in layout (node1: $node1_status, node2: $node2_status)"
    return 1
}

test_manual_mode_cluster_health() {
    log_test "Testing Manual mode cluster health..."

    # Wait for cluster health to show connected nodes
    local timeout=120
    local end_time=$((SECONDS + timeout))

    while [ $SECONDS -lt $end_time ]; do
        local snapshot phase health connected storage_nodes partitions_quorum partitions_total
        snapshot=$(kubectl get garagecluster manual-cluster -n "$NAMESPACE" \
            -o 'jsonpath={.status.phase}{"|"}{.status.health.status}{"|"}{.status.health.connectedNodes}{"|"}{.status.health.storageNodes}{"|"}{.status.health.partitionsQuorum}{"|"}{.status.health.partitions}' 2>/dev/null || true)
        IFS='|' read -r phase health connected storage_nodes partitions_quorum partitions_total <<< "$snapshot"
        if [ "$phase" = "Running" ] && [ "$health" = "healthy" ] && \
            [ "$connected" = "2" ] && [ "$storage_nodes" = "2" ] && \
            [ -n "$partitions_total" ] && [ "$partitions_total" != "0" ] && \
            [ "$partitions_quorum" = "$partitions_total" ]; then
            test_pass "Manual mode cluster is fully healthy with two storage nodes"
            return 0
        fi
        sleep 5
    done

    test_fail "Manual mode cluster health check failed (phase: ${phase:-missing}, health: ${health:-missing}, connected/storage: ${connected:-missing}/${storage_nodes:-missing}, partitions: ${partitions_quorum:-missing}/${partitions_total:-missing})"
    return 1
}

test_manual_mode_bucket_operations() {
    log_test "Testing bucket operations on Manual mode cluster..."

    # Create a bucket on the manual cluster
    cat <<EOF | kubectl apply -f -
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: manual-test-bucket
  namespace: $NAMESPACE
spec:
  clusterRef:
    name: manual-cluster
  globalAlias: manual-test-bucket
EOF

    if check_resource_phase "garagebucket" "manual-test-bucket" "Ready" 60; then
        test_pass "Bucket created on Manual mode cluster"
        kubectl delete garagebucket manual-test-bucket -n "$NAMESPACE" \
            --wait=true --timeout=60s 2>/dev/null || true
        return 0
    fi
    test_fail "Bucket creation on Manual mode cluster failed"
    kubectl delete garagebucket manual-test-bucket -n "$NAMESPACE" \
        --wait=true --timeout=60s 2>/dev/null || true
    return 1
}

test_manual_mode_cleanup() {
    log_test "Testing Manual mode cluster cleanup..."

    # This is whole-store teardown, not a scale-down. With replication.factor=2,
    # neither of the final two storage roles can be removed individually. Delete
    # the GarageCluster so its Destroy finalizer owns the whole-store boundary,
    # requests deletion of every logical GarageNode dependent (including these
    # user-authored Manual nodes), and keeps shared Services/config available
    # until their StatefulSets are gone. Request the parent asynchronously so
    # explicit child deletes happen while its deletion timestamp is visible;
    # a parentless storage GarageNode deliberately retains its finalizer.
    if ! kubectl delete garagecluster manual-cluster -n "$NAMESPACE" \
        --wait=false --request-timeout=15s; then
        test_fail "Could not request Manual GarageCluster Destroy teardown"
        return 1
    fi

    kubectl delete garagenode manual-node-1 -n "$NAMESPACE" \
        --wait=false --request-timeout=15s 2>/dev/null || true
    kubectl delete garagenode manual-node-2 -n "$NAMESPACE" \
        --wait=false --request-timeout=15s 2>/dev/null || true
    if ! wait_for_resource_deleted "garagenode" "manual-node-1" 300; then
        test_fail "GarageNode manual-node-1 did not finish teardown"
        return 1
    fi
    if ! wait_for_resource_deleted "garagenode" "manual-node-2" 300; then
        test_fail "GarageNode manual-node-2 did not finish teardown"
        return 1
    fi

    if ! wait_for_resource_deleted "garagecluster" "manual-cluster" 300; then
        test_fail "Manual GarageCluster did not finish Destroy teardown"
        return 1
    fi

    # GarageNode deletion requests the owned StatefulSet deletion, but owner
    # garbage collection is asynchronous. Wait for the exact children before
    # declaring the manual fixture gone.
    if ! wait_for_resource_deleted "statefulset" "manual-node-1" 120; then
        test_fail "StatefulSet for node 1 was not cleaned up"
        return 1
    fi

    if ! wait_for_resource_deleted "statefulset" "manual-node-2" 120; then
        test_fail "StatefulSet for node 2 was not cleaned up"
        return 1
    fi

    test_pass "Manual mode cluster and nodes cleaned up"
    return 0
}

# ============================================================================
# Cleanup Tests
# ============================================================================

test_full_cleanup() {
    log_test "Testing full resource cleanup..."

    # Delete all test resources
    kubectl delete garagekey --all -n "$NAMESPACE" --wait=true --timeout=60s 2>/dev/null || true
    kubectl delete garagebucket --all -n "$NAMESPACE" --wait=true --timeout=60s 2>/dev/null || true

    # Verify both Kubernetes and Garage-side objects converge. The CR deletion
    # command only waits for the delete requests it observes; the controller
    # may still be revoking the corresponding Garage objects afterwards.
    local cleanup_deadline=$((SECONDS + 180))
    local key_count=0
    local bucket_count=0
    local garage_key_count=-1
    local garage_bucket_count=-1
    while [ "$SECONDS" -lt "$cleanup_deadline" ]; do
        key_count=$(kubectl get garagekey -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l | tr -d ' ')
        bucket_count=$(kubectl get garagebucket -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l | tr -d ' ')

        if [ "$key_count" = "0" ] && [ "$bucket_count" = "0" ]; then
            garage_key_count=-1
            garage_bucket_count=-1
            local garage_keys garage_buckets
            if garage_keys=$(garage_admin_get "/v2/ListKeys" 2>/dev/null) &&
                garage_key_count=$(jq -r \
                    'if type == "array" then length else error("expected an array") end' \
                    <<<"$garage_keys" 2>/dev/null); then
                :
            fi
            if garage_buckets=$(garage_admin_get "/v2/ListBuckets" 2>/dev/null) &&
                garage_bucket_count=$(jq -r \
                    'if type == "array" then length else error("expected an array") end' \
                    <<<"$garage_buckets" 2>/dev/null); then
                :
            fi
            if [ "$garage_key_count" = "0" ] && [ "$garage_bucket_count" = "0" ]; then
                test_pass "All bucket and key CRs and exact Garage-side objects cleaned up"
                return 0
            fi
        fi
        sleep 2
    done

    test_fail "Cleanup incomplete (key CRs: $key_count, bucket CRs: $bucket_count, or Garage-side objects remain)"
    return 1
}

test_cluster_deletion() {
    log_test "Testing GarageCluster deletion..."

    kubectl delete garagecluster garage -n "$NAMESPACE" --wait=true --timeout=300s

    # The parent delete can complete before all owned workloads and Services
    # have disappeared. Wait for each observable child instead of assuming a
    # fixed controller teardown delay.
    if wait_for_resource_deleted "statefulset" "garage-storage-0" 120 && \
        wait_for_resource_deleted "service" "garage" 120; then
        test_pass "GarageCluster and all owned resources deleted"
        return 0
    fi
    test_fail "GarageCluster deletion did not clean up all resources"
    return 1
}

test_recreate_after_deletion() {
    log_test "Testing cluster recreation after deletion..."

    # The default Retain policy deliberately leaves managed claims behind after
    # deleting the entire GarageCluster. The old parent and GarageNode status —
    # the controller-owned proof of those exact PVC UIDs — is gone, so a new
    # same-name cluster must not infer ownership from predictable names or
    # writable annotations. This test exercises a genuinely fresh recreation;
    # remove the isolated fixture's retained claims explicitly first.
    if ! kubectl delete pvc -n "$NAMESPACE" \
        -l 'garage.rajsingh.info/cluster=garage,app.kubernetes.io/managed-by=garage-operator' \
        --ignore-not-found --wait=true --timeout=120s; then
        test_fail "Cluster recreation could not remove the deleted fixture's retained PVCs"
        return 1
    fi

    # Re-apply test resources
    kubectl apply -f hack/test-resources.yaml

    if wait_for_pods_ready "garage.rajsingh.info/cluster=garage" 3 "$TIMEOUT"; then
        # Wait for every terminal readiness signal together under ONE generous timeout.
        # phase lags health by up to the GarageNode controller's 1-min requeue, so a
        # sequential health-then-phase wait races that cadence (the #213/#214/#215 flake).
        if wait_for_cluster_fully_ready 360; then
            test_pass "Cluster successfully recreated after deletion (phase=Running, health=healthy, 3/3 nodes, partitions in quorum)"
            return 0
        fi
    fi
    # Capture the lagging signal so a genuine non-recovery is distinguishable from a slow runner
    local phase health connected pq pt
    phase=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
    health=$(get_cluster_health)
    connected=$(get_connected_nodes)
    pq=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.health.partitionsQuorum}' 2>/dev/null || echo "0")
    pt=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.status.health.partitions}' 2>/dev/null || echo "0")
    test_fail "Cluster recreation failed: phase=$phase health=$health nodes=$connected partitions=$pq/$pt"
    return 1
}

# ============================================================================
# Main Test Flow
# ============================================================================

print_summary() {
    echo ""
    echo "=============================================="
    echo "               TEST SUMMARY"
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

# Shell tests share the same live Garage fixtures. Once one test has failed,
# later tests can otherwise interpret the partially-mutated state as their own
# result and obscure the first failure with a cascade of misleading failures.
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
    log_info "Starting E2E tests for garage-operator"
    log_info "Working directory: $ROOT_DIR"

    cd "$ROOT_DIR"

    # Step 1: Create kind cluster (retry — pulling the kindest/node image from
    # Docker Hub occasionally times out with "context deadline exceeded", which
    # flaked main and dependency PRs).
    log_info "=== Step 1: Creating kind cluster ==="
    if ! kind_cluster_is_absent "$CLUSTER_NAME"; then
        log_error "Refusing to delete pre-existing kind cluster '$CLUSTER_NAME'"
        exit 1
    fi
    local kind_ok=false
    for attempt in 1 2 3; do
        if kind create cluster --name "$CLUSTER_NAME" --image "$KIND_NODE_IMAGE" --wait 90s; then
            CLUSTER_CREATED=true
            CLUSTER_UID=$(kind_cluster_uid "$CLUSTER_NAME" || true)
            if [ -z "$CLUSTER_UID" ]; then
                log_error "Could not record exact ownership of '$CLUSTER_NAME'"
                exit 1
            fi
            kind_ok=true
            break
        fi
        local existing_clusters
        if ! existing_clusters=$(kind get clusters 2>/dev/null); then
            log_error "kind create failed and cluster ownership could not be checked"
            break
        fi
        if grep -Fqx -- "$CLUSTER_NAME" <<<"$existing_clusters"; then
            CLUSTER_UID=$(kind_cluster_uid "$CLUSTER_NAME" || true)
            if [ -n "$CLUSTER_UID" ]; then
                CLUSTER_CREATED=true
                log_error "kind create failed after creating '$CLUSTER_NAME'; recorded its ownership for cleanup"
            else
                log_error "kind create failed and left an unproven cluster named '$CLUSTER_NAME'; refusing deletion"
            fi
            break
        fi
        log_info "kind create cluster failed before creating '$CLUSTER_NAME' (attempt ${attempt}/3); retrying..."
        sleep 10
    done
    if [ "$kind_ok" = false ]; then
        log_error "kind create cluster failed after 3 attempts"
        exit 1
    fi

    # Step 2: Build and load operator image
    if [ "$SKIP_BUILD" = false ]; then
        log_info "=== Step 2: Building operator image ==="
        docker build -t garage-operator:e2e .
    else
        log_info "=== Step 2: Skipping build (--skip-build) ==="
    fi
    # --skip-build reuses an image already present in the host image store; a
    # fresh Kind node still needs it imported before Helm starts the manager.
    kind load docker-image garage-operator:e2e --name "$CLUSTER_NAME"

    # Step 2.5: Install cert-manager (required by the chart's webhook stack)
    log_info "=== Step 2.5: Installing cert-manager ==="
    "$ROOT_DIR/hack/install-cert-manager.sh"

    # Step 3: Deploy operator using Helm chart
    log_info "=== Step 3: Deploying operator via Helm ==="
    helm install garage-operator charts/garage-operator \
        --namespace "$NAMESPACE" \
        --create-namespace \
        -f charts/garage-operator/values-e2e.yaml \
        --wait --timeout 120s

    # helm --wait returns on Deployment Available; the webhook Service
    # endpoint slice may lag a few seconds, so block until it has a Ready
    # address to avoid "connection refused" on the first kubectl apply.
    NAMESPACE="$NAMESPACE" "$ROOT_DIR/hack/wait-for-operator-webhook.sh" "kind-$CLUSTER_NAME"

    # Step 4: Apply test resources. GarageAdminToken owns and generates the
    # immutable static bootstrap Secret selected by the GarageCluster; creating
    # an unowned same-name Secret would correctly be rejected as a collision.
    log_info "=== Step 4: Applying test resources ==="
    kubectl apply -f hack/test-resources.yaml

    # Step 5: Wait for Garage pods and the exact initial topology generation.
    log_info "=== Step 5: Waiting for Garage pods ==="
    wait_for_pods_ready "garage.rajsingh.info/cluster=garage,garage.rajsingh.info/tier=storage" 3 "$TIMEOUT" || {
        log_error "Garage pods failed to start"
        kubectl logs deployment/garage-operator -n "$NAMESPACE" --tail=50
        exit 1
    }
    if ! wait_for_cluster_fully_ready 360 || ! wait_for_storage_rollout_converged garage 360; then
        log_error "Garage cluster did not reach its exact initial ready generation"
        kubectl get garagecluster,garagenode,garageadmintoken -n "$NAMESPACE" -o yaml
        exit 1
    fi

    # ========================================================================
    # Run Tests
    # ========================================================================

    echo ""
    log_info "=========================================="
    log_info "         RUNNING BASIC TESTS"
    log_info "=========================================="

    run_e2e_test test_cluster_creation
    run_e2e_test test_cluster_health
    run_e2e_test test_cluster_conditions
    run_e2e_test test_bucket_creation
    run_e2e_test test_key_creation
    run_e2e_test test_secret_creation
    run_e2e_test test_secret_ownership
    run_e2e_test test_admin_token_resource

    echo ""
    log_info "=========================================="
    log_info "      RUNNING CONNECTIVITY TESTS"
    log_info "=========================================="

    run_e2e_test test_s3_connectivity
    run_e2e_test test_admin_api_connectivity
    run_e2e_test test_metrics_endpoint
    run_e2e_test test_health_endpoint

    echo ""
    log_info "=========================================="
    log_info "     RUNNING INFRASTRUCTURE TESTS"
    log_info "=========================================="

    run_e2e_test test_configmap_update
    run_e2e_test test_services_created
    run_e2e_test test_status_endpoints
    run_e2e_test test_pvc_creation
    run_e2e_test test_finalizers_present
    run_e2e_test test_garagenode_creation

    echo ""
    log_info "=========================================="
    log_info "      RUNNING FEATURE TESTS"
    log_info "=========================================="

    run_e2e_test test_bucket_quotas
    run_e2e_test test_key_permissions
    run_e2e_test test_key_without_secret
    run_e2e_test test_website_bucket
    run_e2e_test test_webapi_endpoint
    run_e2e_test test_local_alias_creation
    run_e2e_test test_key_expiration
    run_e2e_test test_key_never_expires
    run_e2e_test test_key_create_bucket_permission
    run_e2e_test test_bucket_key_permissions
    run_e2e_test test_secret_template_custom_keys

    echo ""
    log_info "=========================================="
    log_info "     RUNNING STATUS VERIFICATION TESTS"
    log_info "=========================================="

    run_e2e_test test_cluster_status_fields
    run_e2e_test test_bucket_status_fields
    run_e2e_test test_key_status_fields
    run_e2e_test test_quota_status_reporting
    run_e2e_test test_observed_generation
    run_e2e_test test_build_info_status
    run_e2e_test test_storage_stats_status
    run_e2e_test test_bucket_mpu_status

    echo ""
    log_info "=========================================="
    log_info "          RUNNING S3 API TESTS"
    log_info "=========================================="

    run_e2e_test test_s3_list_buckets

    echo ""
    log_info "=========================================="
    log_info "    RUNNING CONFIGURATION TESTS"
    log_info "=========================================="

    run_e2e_test test_database_engine_config
    run_e2e_test test_compression_config
    run_e2e_test test_logging_config
    run_e2e_test test_config_change_triggers_restart
    run_e2e_test test_pdb_creation
    run_e2e_test test_gateway_node
    run_e2e_test test_node_with_tags

    echo ""
    log_info "=========================================="
    log_info "    RUNNING ANNOTATION TESTS"
    log_info "=========================================="

    run_e2e_test test_connect_nodes_annotation
    run_e2e_test test_force_layout_apply_annotation
    run_e2e_test test_pause_reconcile_annotation

    echo ""
    log_info "=========================================="
    log_info "       RUNNING UPDATE TESTS"
    log_info "=========================================="

    run_e2e_test test_bucket_quota_update
    run_e2e_test test_key_permission_update
    run_e2e_test test_idempotent_apply

    echo ""
    log_info "=========================================="
    log_info "     RUNNING ERROR HANDLING TESTS"
    log_info "=========================================="

    run_e2e_test test_invalid_cluster_reference
    run_e2e_test test_invalid_bucket_reference
    run_e2e_test test_key_import
    run_e2e_test test_invalid_zone_config
    run_e2e_test test_replication_factor_validation

    echo ""
    log_info "=========================================="
    log_info "      RUNNING CONCURRENCY TESTS"
    log_info "=========================================="

    run_e2e_test test_concurrent_bucket_creation

    echo ""
    log_info "=========================================="
    log_info "       RUNNING DELETION TESTS"
    log_info "=========================================="

    run_e2e_test test_bucket_deletion
    run_e2e_test test_key_deletion

    echo ""
    log_info "=========================================="
    log_info "       RUNNING SCALING TESTS"
    log_info "=========================================="

    run_e2e_test test_scale_subresource
    run_e2e_test test_cluster_scaling
    run_e2e_test test_scale_down_layout_cleanup
    run_e2e_test test_cluster_recovery

    echo ""
    log_info "=========================================="
    log_info "      RUNNING RESILIENCE TESTS"
    log_info "=========================================="

    run_e2e_test test_operator_restart

    echo ""
    log_info "=========================================="
    log_info "    RUNNING MANUAL MODE TESTS"
    log_info "=========================================="

    run_e2e_test test_manual_mode_cluster_creation
    run_e2e_test test_garagenode_statefulset_creation
    run_e2e_test test_manual_mode_second_node
    run_e2e_test test_manual_mode_nodes_in_layout
    run_e2e_test test_manual_mode_cluster_health
    run_e2e_test test_manual_mode_bucket_operations
    run_e2e_test test_manual_mode_cleanup

    echo ""
    log_info "=========================================="
    log_info "       RUNNING CLEANUP TESTS"
    log_info "=========================================="

    run_e2e_test test_full_cleanup
    run_e2e_test test_cluster_deletion
    run_e2e_test test_recreate_after_deletion

    # Print final status
    echo ""
    kubectl get all -n "$NAMESPACE" 2>/dev/null || true
    echo ""
    kubectl get garagecluster,garagebucket,garagekey -n "$NAMESPACE" 2>/dev/null || true

    # Print summary
    print_summary
}

main "$@"
