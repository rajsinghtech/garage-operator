#!/bin/bash
set -euo pipefail

# COSI E2E test script for garage-operator
# Tests the Container Object Storage Interface (COSI) driver
# Usage: ./hack/e2e-cosi.sh [--no-cleanup] [--skip-build]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=hack/e2e-common.sh
source "$SCRIPT_DIR/e2e-common.sh"
CLUSTER_NAME="garage-cosi-e2e"
NAMESPACE="garage-operator-system"
COSI_NAMESPACE="default"
OUT_OF_SCOPE_NAMESPACE="cosi-out-of-scope"
# COSI CRDs require k8s 1.31+ for CEL format validation
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.35.0@sha256:4613778f3cfcd10e615029370f5786704559103cf27bef934597ba562b269661}"
# Keep the shell E2E fixtures on the exact upstream revision used by the Go
# COSI client module in go.mod. Floating main made unrelated upstream changes
# capable of breaking an otherwise unchanged operator PR.
COSI_UPSTREAM_REVISION="cc544691e2ef7ddc2fba972d796ed3188ea46315"
COSI_CONTROLLER_IMAGE="gcr.io/k8s-staging-sig-storage/objectstorage-controller:v20260724-controllerv0.2.0-rc1-297-g23072ad"
COSI_CONTROLLER_IMAGE_PINNED="${COSI_CONTROLLER_IMAGE}@sha256:84fe743766a385a0da2ffd4fd768ba5a933a7df5b231e01b7bc9a4282d50ccba"
AWS_CLI_IMAGE="amazon/aws-cli:2.27.41@sha256:bc6b7bba44ce38f9604ede49c584824af919047ea03fbcc7c7610671fdef95d8"

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

E2E_KUBECONFIG_DIR=$(mktemp -d "${TMPDIR:-/tmp}/garage-cosi-e2e-kubeconfig.XXXXXX")
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

print_summary() {
    echo ""
    echo "============================================"
    echo "  COSI E2E Test Results"
    echo "============================================"
    echo -e "  ${GREEN}Passed:  $TESTS_PASSED${NC}"
    echo -e "  ${RED}Failed:  $TESTS_FAILED${NC}"
    echo -e "  ${YELLOW}Skipped: $TESTS_SKIPPED${NC}"
    echo "============================================"
}

# COSI tests use shared claims and Garage fixtures. A failed prerequisite can
# leave objects in a state that makes every later test misleading, so stop at
# the first failed test and preserve the original failure for diagnostics.
run_e2e_test() {
    local test_name="$1"
    if "$test_name"; then
        return 0
    fi
    log_error "Stopping after $test_name failed; later tests depend on its fixtures"
    print_summary
    collect_debug_info
    return 1
}

dump_debug_info() {
    local cluster="$1"
    local dir="${E2E_DEBUG_DIR:-/tmp/e2e-debug}"
    mkdir -p "$dir" 2>/dev/null || return 0
    kubectl --context "kind-$cluster" get all -A -o wide > "$dir/${cluster}-resources.txt" 2>&1 || true
    kubectl --context "kind-$cluster" get garagecluster,garagenode,garagebucket,garagekey,garageadmintoken -A -o yaml > "$dir/${cluster}-garage-resources.yaml" 2>&1 || true
    kubectl --context "kind-$cluster" get bucketclaim,bucketaccess -A -o yaml > "$dir/${cluster}-cosi-resources.yaml" 2>&1 || true
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
            log_error "Refusing to clean '$CLUSTER_NAME': live kube-system UID does not match this run"
            return 1
        fi
        if ! clear_cosi_bind_denial; then
            log_warn "Could not clear the COSI admission denial before cluster cleanup"
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
        local live_uid
        live_uid=$(kubectl --context "kind-$CLUSTER_NAME" get namespace kube-system \
            -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
        if [ -z "$CLUSTER_UID" ] || [ "$live_uid" != "$CLUSTER_UID" ]; then
            log_error "Refusing to clean '$CLUSTER_NAME': live kube-system UID does not match this run"
            return 1
        fi
        if ! clear_cosi_bind_denial; then
            log_warn "Could not clear the COSI admission denial while retaining the cluster"
        fi
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

ensure_namespace_active() {
    local namespace="$1"
    local timeout="${2:-120}"
    local namespace_json phase end_time create_output

    if ! namespace_json=$(kubectl get namespace "$namespace" --ignore-not-found -o json); then
        log_error "Could not inspect namespace '$namespace'"
        return 1
    fi
    if [ -n "$namespace_json" ]; then
        if ! phase=$(jq -er '.status.phase // empty' <<<"$namespace_json"); then
            log_error "Could not decode namespace '$namespace'"
            return 1
        fi
        if [ "$phase" = "Terminating" ]; then
            log_error "Refusing to use terminating namespace '$namespace'"
            return 1
        fi
    else
        if ! create_output=$(kubectl create namespace "$namespace" 2>&1); then
            # A concurrent creator is safe only after the live object is
            # inspected; do not turn arbitrary create failures into success.
            if ! namespace_json=$(kubectl get namespace "$namespace" --ignore-not-found -o json); then
                log_error "Could not verify namespace '$namespace' after create failure: $create_output"
                return 1
            fi
            if [ -z "$namespace_json" ] || ! phase=$(jq -er '.status.phase // empty' <<<"$namespace_json"); then
                log_error "Namespace '$namespace' was not created: $create_output"
                return 1
            fi
            if [ "$phase" = "Terminating" ]; then
                log_error "Refusing to use terminating namespace '$namespace'"
                return 1
            fi
        fi
    fi

    end_time=$((SECONDS + timeout))
    while [ "$SECONDS" -lt "$end_time" ]; do
        if ! namespace_json=$(kubectl get namespace "$namespace" --ignore-not-found -o json); then
            log_error "Could not inspect namespace '$namespace' while waiting"
            return 1
        fi
        if [ -n "$namespace_json" ]; then
            if ! phase=$(jq -er '.status.phase // empty' <<<"$namespace_json"); then
                log_error "Could not decode namespace '$namespace' while waiting"
                return 1
            fi
            case "$phase" in
                Active)
                    return 0
                    ;;
                Terminating)
                    log_error "Namespace '$namespace' entered Terminating while waiting"
                    return 1
                    ;;
            esac
        fi
        sleep 1
    done

    log_error "Timed out waiting for namespace '$namespace' to become Active"
    return 1
}

cleanup_out_of_scope_fixture() {
    local bound_bucket="${1:-}" cleanup_status=0 output

    # Recover the exact cluster-scoped Bucket identity if the provisioning
    # observation timed out just after the upstream COSI controller created it.
    if [ -z "$bound_bucket" ]; then
        bound_bucket=$(kubectl get bucket -o json 2>/dev/null | python3 -c '
import json, sys
namespace, name = sys.argv[1:]
for item in json.load(sys.stdin).get("items", []):
    ref = item.get("spec", {}).get("bucketClaimRef", {})
    if ref.get("namespace") == namespace and ref.get("name") == name:
        print(item.get("metadata", {}).get("name", ""))
        break
' "$OUT_OF_SCOPE_NAMESPACE" out-of-scope 2>/dev/null || true)
    fi

    if ! output=$(kubectl delete bucketclaim out-of-scope -n "$OUT_OF_SCOPE_NAMESPACE" \
        --ignore-not-found --wait=false --request-timeout=15s 2>&1); then
        log_warn "Could not request out-of-scope BucketClaim deletion: $output"
        cleanup_status=1
    fi
    if ! wait_for_resource_deleted bucketclaim out-of-scope 120 "$OUT_OF_SCOPE_NAMESPACE"; then
        log_warn "Out-of-scope BucketClaim did not finish deleting"
        cleanup_status=1
    fi

    # Request Bucket deletion even if the claim wait failed. The requests are
    # intentionally issued before either wait so a COSI finalizer cannot leave
    # the claim and cluster-scoped Bucket waiting on one another.
    if [ -n "$bound_bucket" ]; then
        if ! output=$(kubectl delete bucket "$bound_bucket" --ignore-not-found \
            --wait=false --request-timeout=15s 2>&1); then
            log_warn "Could not request out-of-scope Bucket/$bound_bucket deletion: $output"
            cleanup_status=1
        fi
        if ! wait_for_resource_deleted bucket "$bound_bucket" 120; then
            log_warn "Out-of-scope Bucket/$bound_bucket did not finish deleting"
            cleanup_status=1
        fi
    fi

    if ! output=$(kubectl delete namespace "$OUT_OF_SCOPE_NAMESPACE" --ignore-not-found \
        --wait=false --request-timeout=15s 2>&1); then
        log_warn "Could not request out-of-scope namespace deletion: $output"
        cleanup_status=1
    fi
    if ! wait_for_resource_deleted namespace "$OUT_OF_SCOPE_NAMESPACE" 120; then
        log_warn "Out-of-scope namespace '$OUT_OF_SCOPE_NAMESPACE' did not finish deleting"
        cleanup_status=1
    fi

    return "$cleanup_status"
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

test_cosi_reconcilers_loaded() {
    log_test "Testing operator runs COSI reconcilers natively (no sidecar)..."

    # Post-refactor: the operator handles Bucket/BucketAccess directly in a
    # single container. The cosi-sidecar container must NOT be present.
    # Inspect the Deployment template, which is the stable source of truth
    # during a rollout. Requiring exactly one currently active Pod made this
    # assertion fail whenever old and new ReplicaSets briefly overlapped.
    local container_count sidecar_count container_summary
    container_summary=$(kubectl get deployment garage-operator -n "$NAMESPACE" \
        -o json 2>/dev/null | python3 -c '
import json, sys
deployment = json.load(sys.stdin)
containers = deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
print("{}:{}".format(
    len(containers),
    sum(container.get("name") == "cosi-sidecar" for container in containers),
))
' 2>/dev/null || echo "0:1")
container_count=${container_summary%%:*}
sidecar_count=${container_summary##*:}

    if [ "$container_count" -eq "1" ] && [ "$sidecar_count" -eq "0" ]; then
        test_pass "Operator runs single container (COSI sidecar removed)"
        return 0
    fi
    test_fail "Unexpected operator containers (count: $container_count, COSI sidecars: $sidecar_count; expected one non-sidecar container)"
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
        bucket_name=$(kubectl get garagebucket -n "$NAMESPACE" -l "garage.rajsingh.info/cosi-managed=true" \
            -o json 2>/dev/null | python3 -c '
import json, sys
items = json.load(sys.stdin).get("items", [])
print(next((item.get("metadata", {}).get("name", "") for item in items), ""))
' 2>/dev/null || true)
        test_pass "Shadow GarageBucket created: $bucket_name"
        return 0
    fi
    test_fail "No shadow GarageBucket found with cosi-managed label"
    return 1
}

test_namespace_scope_enforced() {
    log_test "Testing namespace-scoped COSI provisioning rejects out-of-scope BucketClaims..."
    local buckets_before buckets_after bound_bucket status_json finalizers exact_shadows
    local end_time

    if ! buckets_before=$(garage_admin_count /v2/ListBuckets); then
        test_fail "Could not establish Garage bucket count before namespace-scope test"
        return 1
    fi
    if ! ensure_namespace_active "$OUT_OF_SCOPE_NAMESPACE" 120; then
        test_fail "Out-of-scope namespace '$OUT_OF_SCOPE_NAMESPACE' was not Active"
        return 1
    fi
    cat <<EOF | kubectl apply -f -
apiVersion: objectstorage.k8s.io/v1alpha2
kind: BucketClaim
metadata:
  name: out-of-scope
  namespace: $OUT_OF_SCOPE_NAMESPACE
spec:
  bucketClassName: garage-standard
  protocols: [S3]
EOF

    end_time=$((SECONDS + 120))
    bound_bucket=""
    while [ "$SECONDS" -lt "$end_time" ]; do
        bound_bucket=$(kubectl get bucket -o json 2>/dev/null | python3 -c '
import json, sys
matches = [
    item.get("metadata", {}).get("name", "")
    for item in json.load(sys.stdin).get("items", [])
    if item.get("spec", {}).get("bucketClaimRef", {}).get("namespace") == sys.argv[1]
    and item.get("spec", {}).get("bucketClaimRef", {}).get("name") == sys.argv[2]
]
print(matches[0] if len(matches) == 1 else "")
' "$OUT_OF_SCOPE_NAMESPACE" out-of-scope 2>/dev/null || true)
        [ -n "$bound_bucket" ] && break
        sleep 2
    done
    if [ -z "$bound_bucket" ]; then
        cleanup_out_of_scope_fixture
        test_fail "Upstream COSI controller did not create an out-of-scope Bucket fixture"
        return 1
    fi

    # Observe the out-of-scope object for several seconds. The namespace-scoped
    # operator must ignore it completely: even an error status write would race
    # another scoped instance that legitimately owns it.
    local stable=true
    local stable_end=$((SECONDS + 5))
    while [ "$SECONDS" -lt "$stable_end" ]; do
        status_json=$(kubectl get bucket "$bound_bucket" -o json 2>/dev/null | python3 -c '
import json, sys
print(json.dumps(json.load(sys.stdin).get("status", {}), sort_keys=True, separators=(",", ":")))
' 2>/dev/null || true)
        buckets_after=$(garage_admin_count /v2/ListBuckets 2>/dev/null || true)
        finalizers=$(kubectl get bucket "$bound_bucket" -o jsonpath='{.metadata.finalizers[*]}' 2>/dev/null || true)
        exact_shadows=$(exact_shadow_count garagebucket garage.rajsingh.info/cosi-reservation-owner "$bound_bucket" 2>/dev/null || true)
        if [ "$status_json" != "{}" ] || [[ " $finalizers " == *" garage.rajsingh.info/cosi-protection "* ]] || \
            [ "$exact_shadows" != "0" ] || [ "$buckets_after" != "$buckets_before" ]; then
            stable=false
        fi
        sleep 1
    done

    if ! cleanup_out_of_scope_fixture "$bound_bucket"; then
        test_fail "Out-of-scope COSI fixture cleanup did not converge"
        return 1
    fi

    if [ "$stable" = true ] && [ "$status_json" = "{}" ] && \
        [[ " $finalizers " != *" garage.rajsingh.info/cosi-protection "* ]] && \
        [ "$exact_shadows" = "0" ] && [ "$buckets_after" = "$buckets_before" ]; then
        test_pass "Out-of-scope Bucket was ignored without status, finalizer, shadow, or Garage mutation"
        return 0
    fi
    test_fail "Out-of-scope Bucket mutated state: status=$status_json finalizers=$finalizers shadows=$exact_shadows GarageBuckets=$buckets_before->$buckets_after"
    return 1
}

test_bucket_access_credentials() {
    log_test "Testing BucketAccess creates credentials..."

    kubectl apply -f "$ROOT_DIR/config/samples/cosi/bucketaccessclass.yaml"
    kubectl apply -f "$ROOT_DIR/config/samples/cosi/bucketaccess.yaml"

    if wait_for_cosi_ready "bucketaccess" "my-bucket-access" 120 "$COSI_NAMESPACE"; then
        if ! kubectl get secret my-bucket-creds -n "$COSI_NAMESPACE" >/dev/null 2>&1; then
            test_fail "BucketAccess ready but credentials secret not found"
            return 1
        fi

        local key encoded
        for key in COSI_PROTOCOL COSI_S3_ACCESS_KEY_ID COSI_S3_ACCESS_SECRET_KEY COSI_S3_ENDPOINT COSI_S3_REGION COSI_S3_BUCKET_ID COSI_S3_ADDRESSING_STYLE; do
            encoded=$(kubectl get secret my-bucket-creds -n "$COSI_NAMESPACE" \
                -o "jsonpath={.data.${key}}" 2>/dev/null || true)
            if [ -z "$encoded" ]; then
                test_fail "Credentials secret is missing nonempty $key"
                return 1
            fi
        done

        test_pass "BucketAccess ready with all required nonempty credential fields"
        return 0
    fi

    local status
    status=$(kubectl get bucketaccess my-bucket-access -n "$COSI_NAMESPACE" -o jsonpath='{.status}' 2>/dev/null || echo "{}")
    test_fail "BucketAccess not ready: $status"
    return 1
}

test_bucket_access_data_plane() {
    log_test "Testing COSI credentials with S3 PUT, GET, and DELETE..."

    kubectl delete job cosi-s3-data-plane -n "$COSI_NAMESPACE" \
        --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1 || true
    cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: cosi-s3-data-plane
  namespace: $COSI_NAMESPACE
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 180
  ttlSecondsAfterFinished: 300
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: aws-cli
        image: $AWS_CLI_IMAGE
        imagePullPolicy: IfNotPresent
        command: ["/bin/sh", "-c"]
        args:
        - |
          set -eu
          expected='garage-operator-cosi-data-plane'
          printf '%s' "\$expected" > /tmp/input
          aws --endpoint-url "\$S3_ENDPOINT" --region "\$S3_REGION" \
            s3api put-object --bucket "\$S3_BUCKET_ID" \
            --key e2e/data-plane.txt --body /tmp/input
          aws --endpoint-url "\$S3_ENDPOINT" --region "\$S3_REGION" \
            s3api get-object --bucket "\$S3_BUCKET_ID" \
            --key e2e/data-plane.txt /tmp/output
          test "\$(cat /tmp/output)" = "\$expected"
          aws --endpoint-url "\$S3_ENDPOINT" --region "\$S3_REGION" \
            s3api delete-object --bucket "\$S3_BUCKET_ID" \
            --key e2e/data-plane.txt
          if head_output=\$(aws --endpoint-url "\$S3_ENDPOINT" --region "\$S3_REGION" \
            s3api head-object --bucket "\$S3_BUCKET_ID" \
            --key e2e/data-plane.txt 2>&1); then
            echo "deleted object is still readable" >&2
            exit 1
          fi
          case "\$head_output" in
            *404*|*Not\ Found*|*NoSuchKey*) ;;
            *) echo "unexpected HEAD failure after delete: \$head_output" >&2; exit 1 ;;
          esac
        env:
        - name: AWS_ACCESS_KEY_ID
          valueFrom:
            secretKeyRef:
              name: my-bucket-creds
              key: COSI_S3_ACCESS_KEY_ID
        - name: AWS_SECRET_ACCESS_KEY
          valueFrom:
            secretKeyRef:
              name: my-bucket-creds
              key: COSI_S3_ACCESS_SECRET_KEY
        - name: S3_ENDPOINT
          valueFrom:
            secretKeyRef:
              name: my-bucket-creds
              key: COSI_S3_ENDPOINT
        - name: S3_REGION
          valueFrom:
            secretKeyRef:
              name: my-bucket-creds
              key: COSI_S3_REGION
        - name: S3_BUCKET_ID
          valueFrom:
            secretKeyRef:
              name: my-bucket-creds
              key: COSI_S3_BUCKET_ID
        - name: HOME
          value: /tmp
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
          runAsNonRoot: true
          runAsUser: 1000
          seccompProfile:
            type: RuntimeDefault
EOF

    if kubectl wait --for=condition=Complete job/cosi-s3-data-plane \
        -n "$COSI_NAMESPACE" --timeout=180s; then
        test_pass "COSI credentials completed S3 PUT, GET, content verification, and DELETE"
        return 0
    fi

    kubectl describe job cosi-s3-data-plane -n "$COSI_NAMESPACE" 2>/dev/null || true
    kubectl logs job/cosi-s3-data-plane -n "$COSI_NAMESPACE" 2>/dev/null || true
    test_fail "COSI S3 data-plane operations failed"
    return 1
}

test_shadow_key_created() {
    log_test "Testing shadow GarageKey was created..."

    local count key_name
    count=$(kubectl get garagekey -n "$NAMESPACE" -l "garage.rajsingh.info/cosi-managed=true" --no-headers 2>/dev/null | wc -l | tr -d ' ')

    if [ "$count" -ge "1" ]; then
        while IFS= read -r key_name; do
            [ -n "$key_name" ] || continue
            if kubectl get secret "$key_name" -n "$NAMESPACE" >/dev/null 2>&1; then
                test_fail "COSI shadow GarageKey $key_name leaked a duplicate generated credential Secret"
                return 1
            fi
        done < <(kubectl get garagekey -n "$NAMESPACE" \
            -l "garage.rajsingh.info/cosi-managed=true" \
            -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
        test_pass "COSI shadow GarageKeys exist without shadow-named credential Secrets"
        return 0
    fi
    test_fail "No shadow GarageKey found with cosi-managed label"
    return 1
}

exact_shadow_count() {
    local resource=$1
    local annotation=$2
    local identity=$3

    kubectl get "$resource" -n "$NAMESPACE" -o json 2>/dev/null | python3 -c '
import json, sys
annotation, identity = sys.argv[1:]
print(sum(
    item.get("metadata", {}).get("annotations", {}).get(annotation) == identity
    for item in json.load(sys.stdin).get("items", [])
))
' "$annotation" "$identity"
}

garage_admin_count() {
    local path=$1
    local port token response pf_pid pf_log

    token=$(kubectl get secret garage-admin-token -n "$NAMESPACE" \
        -o 'go-template={{ index .data "admin-token" | base64decode }}')
    if ! start_port_forward service/garage 3903 "$NAMESPACE" 30; then
        return 1
    fi
    pf_pid=$PORT_FORWARD_PID
    port=$PORT_FORWARD_PORT
    pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$port/health" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        return 1
    fi
    response=$(curl --fail --silent --show-error \
        --header "Authorization: Bearer $token" \
        "http://127.0.0.1:$port$path") || {
        stop_port_forward "$pf_pid" "$pf_log"
        return 1
    }
    stop_port_forward "$pf_pid" "$pf_log"
    python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' <<<"$response"
}

garage_admin_status() {
    local path=$1
    local port token status pf_pid pf_log

    token=$(kubectl get secret garage-admin-token -n "$NAMESPACE" \
        -o 'go-template={{ index .data "admin-token" | base64decode }}')
    if ! start_port_forward service/garage 3903 "$NAMESPACE" 30; then
        return 1
    fi
    pf_pid=$PORT_FORWARD_PID
    port=$PORT_FORWARD_PORT
    pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$port/health" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        return 1
    fi
    status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
        --header "Authorization: Bearer $token" \
        "http://127.0.0.1:$port$path") || {
        stop_port_forward "$pf_pid" "$pf_log"
        return 1
    }
    stop_port_forward "$pf_pid" "$pf_log"
    printf '%s\n' "$status"
}

garage_admin_delete_bucket() {
    local bucket_id=$1
    local port token status pf_pid pf_log

    token=$(kubectl get secret garage-admin-token -n "$NAMESPACE" \
        -o 'go-template={{ index .data "admin-token" | base64decode }}')
    if ! start_port_forward service/garage 3903 "$NAMESPACE" 30; then
        return 1
    fi
    pf_pid=$PORT_FORWARD_PID
    port=$PORT_FORWARD_PORT
    pf_log=$PORT_FORWARD_LOG
    if ! wait_for_port_forward "$pf_pid" "http://127.0.0.1:$port/health" 30 "$pf_log"; then
        stop_port_forward "$pf_pid" "$pf_log"
        return 1
    fi
    status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
        --request POST --header "Authorization: Bearer $token" \
        "http://127.0.0.1:$port/v2/DeleteBucket?id=$bucket_id") || {
        stop_port_forward "$pf_pid" "$pf_log"
        return 1
    }
    stop_port_forward "$pf_pid" "$pf_log"
    [ "$status" = "200" ] || [ "$status" = "404" ]
}

wait_for_remote_count() {
    local path=$1
    local expected=$2
    local timeout=$3
    local current
    local end_time=$((SECONDS + timeout))

    while [ "$SECONDS" -lt "$end_time" ]; do
        current=$(garage_admin_count "$path" 2>/dev/null || true)
        if [ "$current" = "$expected" ]; then
            return 0
        fi
        sleep 2
    done
    return 1
}

wait_for_pending_shadow() {
    local resource=$1
    local timeout=$2
    local count identity_annotation
    local end_time=$((SECONDS + timeout))

    identity_annotation='garage.rajsingh.info/cosi-reservation-alias'
    if [ "$resource" = garagekey ]; then
        identity_annotation='garage.rajsingh.info/cosi-account-id'
    fi

    while [ "$SECONDS" -lt "$end_time" ]; do
        count=$(kubectl get "$resource" -n "$NAMESPACE" -o json 2>/dev/null | python3 -c '
import json, sys
items = json.load(sys.stdin).get("items", [])
identity_annotation = sys.argv[1]
print(sum(
    item.get("metadata", {}).get("annotations", {}).get(
        "garage.rajsingh.info/cosi-provisioning-state"
    ) == "pending"
    and bool(item.get("metadata", {}).get("annotations", {}).get(
        identity_annotation
    ))
    for item in items
))
' "$identity_annotation" 2>/dev/null || true)
        if [ "$count" = "1" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

pending_shadow_identity() {
    local resource=$1

    kubectl get "$resource" -n "$NAMESPACE" -o json 2>/dev/null | python3 -c '
import json, sys
resource = sys.argv[1]
items = []
for item in json.load(sys.stdin).get("items", []):
    metadata = item.get("metadata", {})
    annotations = metadata.get("annotations", {})
    if annotations.get("garage.rajsingh.info/cosi-provisioning-state") != "pending":
        continue
    if resource == "garagebucket":
        remote_id = item.get("status", {}).get("bucketId", "")
        reservation = annotations.get("garage.rajsingh.info/cosi-reservation-alias", "")
    else:
        remote_id = item.get("status", {}).get("accessKeyId", "")
        reservation = annotations.get("garage.rajsingh.info/cosi-account-id", "")
    if remote_id and reservation:
        items.append((metadata.get("name", ""), metadata.get("uid", ""), remote_id, reservation))
if len(items) != 1:
    raise SystemExit(1)
item = next(iter(items))
if not all(item):
    raise SystemExit(1)
print("|".join(item))
' "$resource"
}

set_cosi_bind_denial() {
    local enabled=$1
    if [ "$enabled" = true ]; then
        cat <<'EOF' | kubectl apply -f -
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: deny-cosi-shadow-bind
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
    - apiGroups: ["garage.rajsingh.info"]
      apiVersions: ["v1beta1"]
      operations: ["UPDATE"]
      resources: ["garagebuckets", "garagekeys"]
    - apiGroups: [""]
      apiVersions: ["v1"]
      operations: ["UPDATE"]
      resources: ["configmaps"]
  validations:
  - expression: >-
      !(has(oldObject.metadata.annotations) &&
        'garage.rajsingh.info/cosi-provisioning-state' in oldObject.metadata.annotations &&
        oldObject.metadata.annotations['garage.rajsingh.info/cosi-provisioning-state'] == 'pending' &&
        has(object.metadata.annotations) &&
        'garage.rajsingh.info/cosi-provisioning-state' in object.metadata.annotations &&
        object.metadata.annotations['garage.rajsingh.info/cosi-provisioning-state'] == 'bound')
    message: COSI E2E intentionally blocks the pending-to-bound handoff
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: deny-cosi-shadow-bind
spec:
  policyName: deny-cosi-shadow-bind
  validationActions: [Deny]
EOF
        kubectl wait validatingadmissionpolicy/deny-cosi-shadow-bind \
            --for=jsonpath='{.status.observedGeneration}'=1 --timeout=30s

        # Applying a binding only proves it was persisted, not that every API
        # server admission cache has observed it. Probe the exact transition
        # with a harmless ConfigMap before creating the COSI object; otherwise
        # a fast reconcile can bind before the controlled denial is active.
        kubectl delete configmap cosi-bind-denial-probe -n "$NAMESPACE" \
            --ignore-not-found --wait=true --timeout=60s >/dev/null
        kubectl create configmap cosi-bind-denial-probe -n "$NAMESPACE" \
            --from-literal=probe=admission-readiness >/dev/null
        kubectl annotate configmap cosi-bind-denial-probe -n "$NAMESPACE" \
            garage.rajsingh.info/cosi-provisioning-state=pending >/dev/null
        local denial_output end_time
        end_time=$((SECONDS + 30))
        while [ "$SECONDS" -lt "$end_time" ]; do
            if denial_output=$(kubectl annotate configmap cosi-bind-denial-probe \
                -n "$NAMESPACE" --dry-run=server --overwrite -o name \
                garage.rajsingh.info/cosi-provisioning-state=bound 2>&1); then
                sleep 1
                continue
            fi
            if grep -Fq 'COSI E2E intentionally blocks the pending-to-bound handoff' \
                <<<"$denial_output"; then
                return 0
            fi
            log_error "Admission readiness probe failed unexpectedly: $denial_output"
            return 1
        done
        log_error "Admission policy binding did not become active within 30s"
        return 1
    fi
    kubectl delete validatingadmissionpolicybinding deny-cosi-shadow-bind \
        --ignore-not-found --wait=true --timeout=60s
    kubectl delete configmap cosi-bind-denial-probe -n "$NAMESPACE" \
        --ignore-not-found --wait=true --timeout=60s >/dev/null
}

clear_cosi_bind_denial() {
    local clusters cleanup_status=0
    if ! clusters=$(kind get clusters 2>/dev/null); then
        log_error "Could not enumerate Kind clusters while clearing the COSI admission denial"
        return 1
    fi
    if ! grep -Fqx -- "$CLUSTER_NAME" <<<"$clusters"; then
        return 0
    fi
    kubectl --context "kind-$CLUSTER_NAME" delete \
        validatingadmissionpolicybinding deny-cosi-shadow-bind \
        --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1 || cleanup_status=1
    kubectl --context "kind-$CLUSTER_NAME" delete \
        validatingadmissionpolicy deny-cosi-shadow-bind \
        --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1 || cleanup_status=1
    kubectl --context "kind-$CLUSTER_NAME" delete \
        configmap cosi-bind-denial-probe -n "$NAMESPACE" \
        --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1 || cleanup_status=1
    return "$cleanup_status"
}

verify_restart_reservation() {
    local shadow_resource=$1
    local admin_path=$2
    local expected_remote_count=$3
    local ready_resource=$4
    local ready_name=$5
    local shadows_before=$6
    local shadows_after identity_before identity_after identity_bound
    local shadow_name shadow_uid remote_id remote_path

    if ! wait_for_pending_shadow "$shadow_resource" 120 || \
        ! wait_for_remote_count "$admin_path" "$expected_remote_count" 120; then
        log_error "$shadow_resource did not reach the controlled post-create/pre-bind window"
        clear_cosi_bind_denial
        return 1
    fi

    if ! identity_before=$(pending_shadow_identity "$shadow_resource"); then
        log_error "$shadow_resource pending reservation did not expose one exact durable identity"
        clear_cosi_bind_denial
        return 1
    fi
    IFS='|' read -r shadow_name shadow_uid remote_id _ <<<"$identity_before"
    if [ "$shadow_resource" = garagebucket ]; then
        remote_path="/v2/GetBucketInfo?id=$remote_id"
    else
        remote_path="/v2/GetKeyInfo?id=$remote_id"
    fi
    if [ "$(garage_admin_status "$remote_path" 2>/dev/null || true)" != "200" ]; then
        log_error "$shadow_resource exact pending remote identity $remote_id is absent"
        clear_cosi_bind_denial
        return 1
    fi

    kubectl rollout restart deployment/garage-operator -n "$NAMESPACE"
    if ! kubectl rollout status deployment/garage-operator -n "$NAMESPACE" --timeout=120s; then
        log_error "Operator did not restart while recovering $shadow_resource"
        clear_cosi_bind_denial
        return 1
    fi
    if ! wait_for_pending_shadow "$shadow_resource" 10 || \
        [ "$(garage_admin_count "$admin_path")" != "$expected_remote_count" ]; then
        log_error "$shadow_resource restart created a duplicate or lost its pending identity"
        clear_cosi_bind_denial
        return 1
    fi
    if ! identity_after=$(pending_shadow_identity "$shadow_resource") || \
        [ "$identity_after" != "$identity_before" ] || \
        [ "$(garage_admin_status "$remote_path" 2>/dev/null || true)" != "200" ]; then
        log_error "$shadow_resource restart did not preserve shadow UID, reservation, and exact remote ID"
        clear_cosi_bind_denial
        return 1
    fi

    if ! set_cosi_bind_denial false; then
        log_error "Could not remove the controlled admission denial"
        clear_cosi_bind_denial
        return 1
    fi
    if ! wait_for_cosi_ready "$ready_resource" "$ready_name" 120 "$COSI_NAMESPACE"; then
        log_error "$ready_resource/$ready_name did not bind after removing the denial"
        clear_cosi_bind_denial
        return 1
    fi
    shadows_after=$(kubectl get "$shadow_resource" -n "$NAMESPACE" \
        -l 'garage.rajsingh.info/cosi-managed=true' -o name | wc -l | tr -d ' ')
    if [ "$shadow_resource" = garagebucket ]; then
        identity_bound=$(kubectl get "$shadow_resource" "$shadow_name" -n "$NAMESPACE" \
            -o jsonpath='{.metadata.uid}{"|"}{.status.bucketId}' 2>/dev/null || true)
    else
        identity_bound=$(kubectl get "$shadow_resource" "$shadow_name" -n "$NAMESPACE" \
            -o jsonpath='{.metadata.uid}{"|"}{.status.accessKeyId}' 2>/dev/null || true)
    fi
    if [ "$shadows_after" -ne $((shadows_before + 1)) ] || \
        [ "$(garage_admin_count "$admin_path")" != "$expected_remote_count" ] || \
        [ "$identity_bound" != "$shadow_uid|$remote_id" ] || \
        [ "$(garage_admin_status "$remote_path" 2>/dev/null || true)" != "200" ]; then
        log_error "$ready_resource/$ready_name did not converge to exactly one shadow and remote object"
        clear_cosi_bind_denial
        return 1
    fi
}

test_crash_safe_reservations() {
    log_test "Testing COSI reservation recovery across operator restarts..."

    local buckets_before keys_before bucket_shadows_before key_shadows_before
    local buckets_expected keys_expected
    if ! buckets_before=$(garage_admin_count /v2/ListBuckets) || \
        ! keys_before=$(garage_admin_count /v2/ListKeys); then
        test_fail "Could not establish initial Garage bucket/key counts"
        return 1
    fi
    bucket_shadows_before=$(kubectl get garagebucket -n "$NAMESPACE" \
        -l 'garage.rajsingh.info/cosi-managed=true' -o name | wc -l | tr -d ' ')
    key_shadows_before=$(kubectl get garagekey -n "$NAMESPACE" \
        -l 'garage.rajsingh.info/cosi-managed=true' -o name | wc -l | tr -d ' ')
    buckets_expected=$((buckets_before + 1))
    keys_expected=$((keys_before + 1))

    if ! set_cosi_bind_denial true; then
        test_fail "Could not activate controlled bucket bind denial"
        return 1
    fi
    cat <<EOF | kubectl apply -f -
apiVersion: objectstorage.k8s.io/v1alpha2
kind: BucketClaim
metadata:
  name: restart-recovery-bucket
  namespace: $COSI_NAMESPACE
spec:
  bucketClassName: garage-standard
  protocols: [S3]
EOF
    if ! verify_restart_reservation garagebucket /v2/ListBuckets "$buckets_expected" \
        bucketclaim restart-recovery-bucket "$bucket_shadows_before"; then
        test_fail "Bucket reservation did not recover safely across restart"
        return 1
    fi

    if ! set_cosi_bind_denial true; then
        test_fail "Could not activate controlled key bind denial"
        return 1
    fi
    cat <<EOF | kubectl apply -f -
apiVersion: objectstorage.k8s.io/v1alpha2
kind: BucketAccess
metadata:
  name: restart-recovery-access
  namespace: $COSI_NAMESPACE
spec:
  bucketAccessClassName: garage-readwrite
  protocol: S3
  bucketClaims:
  - bucketClaimName: restart-recovery-bucket
    accessMode: ReadWrite
    accessSecretName: restart-recovery-creds
EOF
    if ! verify_restart_reservation garagekey /v2/ListKeys "$keys_expected" \
        bucketaccess restart-recovery-access "$key_shadows_before"; then
        test_fail "Key reservation did not recover safely across restart"
        return 1
    fi
    clear_cosi_bind_denial

    test_pass "COSI bucket and key reservations recovered without duplicate Garage objects"
    return 0
}

test_bucket_access_cleanup() {
    log_test "Testing BucketAccess cleanup..."
    local account_id unrelated_account_id remote_status unrelated_status exact_shadows unrelated_shadows
    account_id=$(kubectl get bucketaccess restart-recovery-access -n "$COSI_NAMESPACE" \
        -o jsonpath='{.status.accountID}' 2>/dev/null || true)
    unrelated_account_id=$(kubectl get bucketaccess my-bucket-access -n "$COSI_NAMESPACE" \
        -o jsonpath='{.status.accountID}' 2>/dev/null || true)
    if [ -z "$account_id" ] || [ -z "$unrelated_account_id" ] || \
        [ "$account_id" = "$unrelated_account_id" ]; then
        test_fail "Could not establish distinct exact target and unrelated BucketAccess identities"
        return 1
    fi
    if [ "$(exact_shadow_count garagekey garage.rajsingh.info/cosi-account-id "$account_id")" != "1" ] || \
        [ "$(exact_shadow_count garagekey garage.rajsingh.info/cosi-account-id "$unrelated_account_id")" != "1" ] || \
        ! kubectl get secret my-bucket-creds -n "$COSI_NAMESPACE" >/dev/null 2>&1; then
        test_fail "Exact target and unrelated BucketAccess fixtures were not intact before cleanup"
        return 1
    fi

    kubectl delete bucketaccess restart-recovery-access -n "$COSI_NAMESPACE" \
        --wait=false --request-timeout=15s
    local end_time=$((SECONDS + 120))
    while [ "$SECONDS" -lt "$end_time" ]; do
        exact_shadows=$(exact_shadow_count garagekey garage.rajsingh.info/cosi-account-id "$account_id" 2>/dev/null || true)
        unrelated_shadows=$(exact_shadow_count garagekey garage.rajsingh.info/cosi-account-id "$unrelated_account_id" 2>/dev/null || true)
        remote_status=$(garage_admin_status "/v2/GetKeyInfo?id=$account_id" 2>/dev/null || true)
        unrelated_status=$(garage_admin_status "/v2/GetKeyInfo?id=$unrelated_account_id" 2>/dev/null || true)
        if ! kubectl get bucketaccess restart-recovery-access \
            -n "$COSI_NAMESPACE" >/dev/null 2>&1 && \
            ! kubectl get secret restart-recovery-creds \
                -n "$COSI_NAMESPACE" >/dev/null 2>&1 && \
            [ "$exact_shadows" = "0" ] && [ "$remote_status" = "404" ] && \
            [ "$unrelated_shadows" = "1" ] && [ "$unrelated_status" = "200" ] && \
            kubectl get bucketaccess my-bucket-access -n "$COSI_NAMESPACE" >/dev/null 2>&1 && \
            kubectl get secret my-bucket-creds -n "$COSI_NAMESPACE" >/dev/null 2>&1; then
            test_pass "BucketAccess deletion revoked its exact key, shadow, and Secret while preserving the unrelated access"
            return 0
        fi
        sleep 2
    done

    test_fail "BucketAccess deletion did not converge to exact key/shadow cleanup"
    return 1
}

test_bucket_cleanup() {
    log_test "Testing direct COSI Bucket cleanup..."
    local bound_bucket bucket_id unrelated_bound_bucket unrelated_bucket_id
    local remote_status unrelated_status exact_shadows unrelated_shadows

    bound_bucket=$(kubectl get bucketclaim restart-recovery-bucket \
        -n "$COSI_NAMESPACE" -o jsonpath='{.status.boundBucketName}' 2>/dev/null || true)
    if [ -z "$bound_bucket" ]; then
        test_fail "Could not resolve the bound Bucket for restart-recovery-bucket"
        return 1
    fi
    if ! kubectl get bucket "$bound_bucket" >/dev/null 2>&1; then
        test_fail "Bound Bucket $bound_bucket does not exist before deletion"
        return 1
    fi
    bucket_id=$(kubectl get bucket "$bound_bucket" -o jsonpath='{.status.bucketID}' 2>/dev/null || true)
    unrelated_bound_bucket=$(kubectl get bucketclaim my-bucket -n "$COSI_NAMESPACE" \
        -o jsonpath='{.status.boundBucketName}' 2>/dev/null || true)
    unrelated_bucket_id=$(kubectl get bucket "$unrelated_bound_bucket" \
        -o jsonpath='{.status.bucketID}' 2>/dev/null || true)
    if [ -z "$bucket_id" ] || [ -z "$unrelated_bucket_id" ] || \
        [ "$bucket_id" = "$unrelated_bucket_id" ]; then
        test_fail "Could not establish distinct exact target and unrelated Bucket identities"
        return 1
    fi
    if [ "$(exact_shadow_count garagebucket garage.rajsingh.info/cosi-bucket-id "$bucket_id")" != "1" ] || \
        [ "$(exact_shadow_count garagebucket garage.rajsingh.info/cosi-bucket-id "$unrelated_bucket_id")" != "1" ]; then
        test_fail "Exact target and unrelated Bucket shadows were not intact before cleanup"
        return 1
    fi

    if ! kubectl delete bucket "$bound_bucket" --wait=false --request-timeout=15s; then
        test_fail "Could not request deletion of bound Bucket $bound_bucket"
        return 1
    fi
    local end_time=$((SECONDS + 120))
    while [ "$SECONDS" -lt "$end_time" ]; do
        exact_shadows=$(exact_shadow_count garagebucket garage.rajsingh.info/cosi-bucket-id "$bucket_id" 2>/dev/null || true)
        unrelated_shadows=$(exact_shadow_count garagebucket garage.rajsingh.info/cosi-bucket-id "$unrelated_bucket_id" 2>/dev/null || true)
        remote_status=$(garage_admin_status "/v2/GetBucketInfo?id=$bucket_id" 2>/dev/null || true)
        unrelated_status=$(garage_admin_status "/v2/GetBucketInfo?id=$unrelated_bucket_id" 2>/dev/null || true)
        if ! kubectl get bucket "$bound_bucket" >/dev/null 2>&1 && \
            [ "$exact_shadows" = "0" ] && [ "$remote_status" = "404" ] && \
            [ "$unrelated_shadows" = "1" ] && [ "$unrelated_status" = "200" ] && \
            kubectl get bucketclaim my-bucket -n "$COSI_NAMESPACE" >/dev/null 2>&1 && \
            kubectl get bucket "$unrelated_bound_bucket" >/dev/null 2>&1; then
            test_pass "Bound Bucket deletion removed its exact Garage bucket and shadow while preserving the unrelated fixture"
            return 0
        fi
        sleep 2
    done

    test_fail "Bound Bucket deletion did not converge to exact bucket/shadow cleanup"
    return 1
}

test_bucket_claim_cleanup() {
    log_test "Testing BucketClaim cleanup..."
    local claim_name=delete-policy-cleanup
    local bound_bucket bucket_id
    local buckets_before buckets_after_create shadows_before shadows_after_create
    local buckets_now shadows_now exact_shadows remote_status
    local end_time

    if ! buckets_before=$(garage_admin_count /v2/ListBuckets); then
        test_fail "Could not establish Garage bucket count before BucketClaim cleanup"
        return 1
    fi
    shadows_before=$(kubectl get garagebucket -n "$NAMESPACE" \
        -l 'garage.rajsingh.info/cosi-managed=true' -o name | wc -l | tr -d ' ')

    cat <<EOF | kubectl apply -f -
apiVersion: objectstorage.k8s.io/v1alpha2
kind: BucketClaim
metadata:
  name: $claim_name
  namespace: $COSI_NAMESPACE
spec:
  bucketClassName: garage-standard
  protocols: [S3]
EOF
    if ! wait_for_cosi_ready bucketclaim "$claim_name" 120 "$COSI_NAMESPACE"; then
        test_fail "Delete-policy BucketClaim did not become ready"
        return 1
    fi

    bound_bucket=$(kubectl get bucketclaim "$claim_name" -n "$COSI_NAMESPACE" \
        -o jsonpath='{.status.boundBucketName}' 2>/dev/null || true)
    if [ -z "$bound_bucket" ]; then
        test_fail "Delete-policy BucketClaim has no bound Bucket name"
        return 1
    fi
    bucket_id=$(kubectl get bucket "$bound_bucket" -o jsonpath='{.status.bucketID}' 2>/dev/null || true)
    buckets_after_create=$(garage_admin_count /v2/ListBuckets 2>/dev/null || true)
    shadows_after_create=$(kubectl get garagebucket -n "$NAMESPACE" \
        -l 'garage.rajsingh.info/cosi-managed=true' -o name | wc -l | tr -d ' ')
    if [ -z "$bucket_id" ] || \
        [ "$buckets_after_create" != "$((buckets_before + 1))" ] || \
        [ "$shadows_after_create" != "$((shadows_before + 1))" ]; then
        test_fail "Delete-policy claim did not create exactly one bound Bucket, shadow, and Garage bucket"
        return 1
    fi

    kubectl delete bucketclaim "$claim_name" -n "$COSI_NAMESPACE" \
        --wait=false --request-timeout=15s
    end_time=$((SECONDS + 180))
    while [ "$SECONDS" -lt "$end_time" ]; do
        buckets_now=$(garage_admin_count /v2/ListBuckets 2>/dev/null || true)
        shadows_now=$(kubectl get garagebucket -n "$NAMESPACE" \
            -l 'garage.rajsingh.info/cosi-managed=true' -o name | wc -l | tr -d ' ')
        exact_shadows=$(exact_shadow_count garagebucket garage.rajsingh.info/cosi-bucket-id "$bucket_id" 2>/dev/null || true)
        remote_status=$(garage_admin_status "/v2/GetBucketInfo?id=$bucket_id" 2>/dev/null || true)
        if ! kubectl get bucketclaim "$claim_name" -n "$COSI_NAMESPACE" >/dev/null 2>&1 && \
            ! kubectl get bucket "$bound_bucket" >/dev/null 2>&1 && \
            [ "$exact_shadows" = "0" ] && [ "$shadows_now" = "$shadows_before" ] && \
            [ "$remote_status" = "404" ] && [ "$buckets_now" = "$buckets_before" ]; then
            test_pass "Delete-policy BucketClaim removed its claim, bound Bucket, exact shadow, and Garage bucket"
            return 0
        fi
        sleep 2
    done

    test_fail "BucketClaim Delete policy did not converge to exact Kubernetes and Garage cleanup"
    return 1
}

test_bucket_retain_cleanup() {
    log_test "Testing COSI Retain removes Kubernetes ownership without deleting Garage bucket..."
    local claim_name=retain-policy-cleanup
    local class_name=garage-retain
    local bound_bucket bucket_id exact_shadows remote_status end_time

    cat <<EOF | kubectl apply -f -
apiVersion: objectstorage.k8s.io/v1alpha2
kind: BucketClass
metadata:
  name: $class_name
spec:
  driverName: garage.rajsingh.info
  deletionPolicy: Retain
  parameters:
    clusterRef: garage
    clusterNamespace: $NAMESPACE
---
apiVersion: objectstorage.k8s.io/v1alpha2
kind: BucketClaim
metadata:
  name: $claim_name
  namespace: $COSI_NAMESPACE
spec:
  bucketClassName: $class_name
  protocols: [S3]
EOF
    if ! wait_for_cosi_ready bucketclaim "$claim_name" 120 "$COSI_NAMESPACE"; then
        test_fail "Retain-policy BucketClaim did not become ready"
        return 1
    fi
    bound_bucket=$(kubectl get bucketclaim "$claim_name" -n "$COSI_NAMESPACE" \
        -o jsonpath='{.status.boundBucketName}' 2>/dev/null || true)
    bucket_id=$(kubectl get bucket "$bound_bucket" -o jsonpath='{.status.bucketID}' 2>/dev/null || true)
    if [ -z "$bound_bucket" ] || [ -z "$bucket_id" ]; then
        test_fail "Retain-policy claim has no exact bound Bucket identity"
        return 1
    fi

    kubectl delete bucketclaim "$claim_name" -n "$COSI_NAMESPACE" \
        --wait=false --request-timeout=15s
    end_time=$((SECONDS + 120))
    while kubectl get bucketclaim "$claim_name" -n "$COSI_NAMESPACE" >/dev/null 2>&1 && \
        [ "$SECONDS" -lt "$end_time" ]; do
        sleep 2
    done
    if kubectl get bucketclaim "$claim_name" -n "$COSI_NAMESPACE" >/dev/null 2>&1; then
        test_fail "Retain-policy BucketClaim did not disappear"
        return 1
    fi
    kubectl delete bucket "$bound_bucket" --wait=false --request-timeout=15s

    end_time=$((SECONDS + 120))
    while [ "$SECONDS" -lt "$end_time" ]; do
        exact_shadows=$(exact_shadow_count garagebucket garage.rajsingh.info/cosi-bucket-id "$bucket_id" 2>/dev/null || true)
        remote_status=$(garage_admin_status "/v2/GetBucketInfo?id=$bucket_id" 2>/dev/null || true)
        if ! kubectl get bucket "$bound_bucket" >/dev/null 2>&1 && \
            [ "$exact_shadows" = "0" ] && [ "$remote_status" = "200" ]; then
            if ! garage_admin_delete_bucket "$bucket_id"; then
                test_fail "Retained Garage bucket could not be explicitly cleaned up"
                return 1
            fi
            local cleanup_end=$((SECONDS + 60))
            while [ "$SECONDS" -lt "$cleanup_end" ] && \
                [ "$(garage_admin_status "/v2/GetBucketInfo?id=$bucket_id" 2>/dev/null || true)" != "404" ]; do
                sleep 2
            done
            if [ "$(garage_admin_status "/v2/GetBucketInfo?id=$bucket_id" 2>/dev/null || true)" != "404" ]; then
                test_fail "Explicit retained Garage bucket cleanup did not converge"
                return 1
            fi
            if ! kubectl delete bucketclass "$class_name" --ignore-not-found \
                --wait=true --timeout=60s; then
                test_fail "Retain BucketClass cleanup failed"
                return 1
            fi
            test_pass "Retain removed claim, Bucket, and shadow while preserving the exact Garage bucket"
            return 0
        fi
        sleep 2
    done

    garage_admin_delete_bucket "$bucket_id" >/dev/null 2>&1 || true
    kubectl delete bucketclass "$class_name" --ignore-not-found \
        --wait=true --timeout=60s >/dev/null 2>&1 || true
    test_fail "Retain did not converge to Kubernetes-only cleanup with the Garage bucket preserved"
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
if ! kind_cluster_is_absent "$CLUSTER_NAME"; then
    log_error "Refusing to delete pre-existing kind cluster '$CLUSTER_NAME'"
    log_error "Delete it explicitly or choose an isolated environment before rerunning"
    exit 1
fi
if ! kind create cluster --name "$CLUSTER_NAME" --image "$KIND_NODE_IMAGE" --wait 120s; then
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

# Build and load operator image
if [ "$SKIP_BUILD" = false ]; then
    log_info "Building operator image..."
    cd "$ROOT_DIR"
    docker build -t garage-operator:cosi-e2e .
fi

log_info "Loading operator image into kind..."
kind load docker-image garage-operator:cosi-e2e --name "$CLUSTER_NAME"

# Install COSI CRDs
log_info "Installing COSI CRDs..."
for crd in bucketclaims bucketaccesses bucketclasses bucketaccessclasses buckets; do
    kubectl apply -f "https://raw.githubusercontent.com/kubernetes-sigs/container-object-storage-interface/${COSI_UPSTREAM_REVISION}/client/config/crd/objectstorage.k8s.io_${crd}.yaml"
done

# Install COSI controller
log_info "Installing COSI controller..."
kubectl kustomize \
    "github.com/kubernetes-sigs/container-object-storage-interface/controller?ref=${COSI_UPSTREAM_REVISION}" |
    "$ROOT_DIR/hack/pin-manifest-images.sh" \
        "${COSI_CONTROLLER_IMAGE}=${COSI_CONTROLLER_IMAGE_PINNED}" |
    kubectl apply -f -

# Wait for COSI controller to be ready
log_info "Waiting for COSI controller..."
if ! kubectl wait deployment/container-object-storage-controller -n container-object-storage-system \
    --for=condition=Available --timeout=120s; then
    log_error "COSI controller failed to become available"
    collect_debug_info
    exit 1
fi

# Create namespace
log_info "Creating namespace '$NAMESPACE'..."
if ! ensure_namespace_active "$NAMESPACE" 120; then
    collect_debug_info
    exit 1
fi

# Deploy operator with COSI enabled via Helm (includes CRDs)
log_info "Deploying operator with COSI enabled..."
cd "$ROOT_DIR"
make manifests generate

# Install cert-manager — the chart's webhook stack requires it.
"$ROOT_DIR/hack/install-cert-manager.sh"

helm install garage-operator "$ROOT_DIR/charts/garage-operator" \
    -n "$NAMESPACE" \
    -f "$ROOT_DIR/charts/garage-operator/values-cosi-e2e.yaml" \
    --wait --timeout 120s

if ! NAMESPACE="$NAMESPACE" "$ROOT_DIR/hack/wait-for-operator-webhook.sh" "kind-$CLUSTER_NAME"; then
    log_error "Operator webhook failed to become ready"
    collect_debug_info
    exit 1
fi

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
if ! wait_for_pods_ready "garage.rajsingh.info/cluster=garage" 1 120; then
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
run_e2e_test test_cosi_reconcilers_loaded
run_e2e_test test_garage_cluster_ready
run_e2e_test test_bucket_claim_bound
run_e2e_test test_shadow_bucket_created
run_e2e_test test_namespace_scope_enforced
run_e2e_test test_bucket_access_credentials
run_e2e_test test_bucket_access_data_plane
run_e2e_test test_shadow_key_created
run_e2e_test test_crash_safe_reservations
run_e2e_test test_bucket_access_cleanup
run_e2e_test test_bucket_cleanup
run_e2e_test test_bucket_claim_cleanup
run_e2e_test test_bucket_retain_cleanup

# Print summary
print_summary

if [ "$TESTS_FAILED" -gt 0 ]; then
    collect_debug_info
    exit 1
fi

log_info "All COSI E2E tests passed!"
