#!/bin/bash
set -euo pipefail

# Upgrade E2E: install the released operator chart, let it create a live
# Garage cluster, bucket and key, then `helm upgrade` to the PR build and
# assert that nothing was disrupted or lost:
#   - an in-cluster S3 reader and Garage /health probe run every second across
#     the whole upgrade; no failed read is allowed unless the upgrade rolled
#     Garage pods, and even then never more than a few consecutive failures
#   - GarageCluster/Bucket/Key keep their identities (bucket ID, access key ID,
#     credential Secret bytes, cluster UID) and return to Ready
#   - the Garage layout keeps the same node roles (no data movement)
#   - the object written before the upgrade reads back byte-for-byte
#   - the upgraded operator still provisions a new bucket and key that work
#
# Usage: ./hack/e2e-upgrade.sh [--no-cleanup] [--skip-build]
# Env:   UPGRADE_FROM_VERSION  released chart version (default: 0.8.1)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=hack/e2e-common.sh
source "$SCRIPT_DIR/e2e-common.sh"

CLUSTER_NAME="${KIND_CLUSTER:-garage-upgrade-e2e}"
NAMESPACE="garage-operator-system"
FROM_VERSION="${UPGRADE_FROM_VERSION:-0.8.1}"
CHART_REF="oci://ghcr.io/rajsinghtech/charts/garage-operator"
CURL_IMAGE="curlimages/curl:8.14.1@sha256:9a1ed35addb45476afa911696297f8e115993df459278ed036182dd2cd22b67b"
CANARY_BODY="garage-operator upgrade canary $(date +%s)-$RANDOM"
S3_URL="http://garage.${NAMESPACE}.svc:3900"
ADMIN_URL="http://garage.${NAMESPACE}.svc:3903"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

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

E2E_KUBECONFIG_DIR=$(mktemp -d "${TMPDIR:-/tmp}/garage-upgrade-e2e-kubeconfig.XXXXXX")
export KUBECONFIG="$E2E_KUBECONFIG_DIR/config"
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/garage-upgrade-e2e.XXXXXX")
CLUSTER_CREATED=false
CLUSTER_UID=""
FAILURES=0

fail() {
    log_error "FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

dump_debug_info() {
    local dir="${E2E_DEBUG_DIR:-/tmp/e2e-debug}"
    mkdir -p "$dir" 2>/dev/null || return 0
    kubectl get all -A -o wide >"$dir/${CLUSTER_NAME}-resources.txt" 2>&1 || true
    kubectl get garagecluster,garagenode,garagebucket,garagekey,garageadmintoken -A -o yaml >"$dir/${CLUSTER_NAME}-garage-resources.yaml" 2>&1 || true
    kubectl get events -A --sort-by=.lastTimestamp >"$dir/${CLUSTER_NAME}-events.txt" 2>&1 || true
    kubectl logs deployment/garage-operator -n "$NAMESPACE" --tail=3000 >"$dir/${CLUSTER_NAME}-operator.log" 2>&1 || true
    kubectl logs deployment/garage-operator -n "$NAMESPACE" --tail=3000 --previous >"$dir/${CLUSTER_NAME}-operator-previous.log" 2>&1 || true
    kubectl logs upgrade-probe -n "$NAMESPACE" >"$dir/${CLUSTER_NAME}-probe.log" 2>&1 || true
    cp "$WORK_DIR"/*.txt "$WORK_DIR"/*.json "$dir/" 2>/dev/null || true
}

cleanup() {
    local status=$?
    if [ "$CLUSTER_CREATED" = true ]; then
        local live_uid
        live_uid=$(kind_cluster_uid "$CLUSTER_NAME" || true)
        if [ -n "$CLUSTER_UID" ] && [ "$live_uid" = "$CLUSTER_UID" ]; then
            dump_debug_info
            if [ "$CLEANUP" = true ]; then
                log_info "Deleting kind cluster $CLUSTER_NAME"
                kind delete cluster --name "$CLUSTER_NAME" || status=1
            fi
        else
            log_error "Refusing to clean '$CLUSTER_NAME': live kube-system UID does not match this run"
            status=1
        fi
    fi
    if [ "$CLEANUP" = true ]; then
        rm -rf "$WORK_DIR" "$E2E_KUBECONFIG_DIR"
    fi
    exit "$status"
}
trap cleanup EXIT

wait_for_condition() {
    local kind="$1" name="$2" timeout="$3"
    kubectl wait --for=condition=Ready "$kind/$name" -n "$NAMESPACE" --timeout="${timeout}s" >/dev/null
}

# Phase Running, healthy, 3 connected nodes, every partition in quorum.
wait_for_cluster_healthy() {
    local timeout="$1" end_time=$((SECONDS + $1)) snapshot
    while [ $SECONDS -lt $end_time ]; do
        snapshot=$(kubectl get garagecluster garage -n "$NAMESPACE" \
            -o 'jsonpath={.status.phase}|{.status.health.status}|{.status.health.connectedNodes}|{.status.health.partitionsQuorum}|{.status.health.partitions}' 2>/dev/null || true)
        IFS='|' read -r phase health connected pq pt <<<"$snapshot"
        if [ "$phase" = "Running" ] && [ "$health" = "healthy" ] && [ "$connected" = "3" ] && [ -n "$pt" ] && [ "$pt" != "0" ] && [ "$pq" = "$pt" ]; then
            return 0
        fi
        sleep 5
    done
    log_error "GarageCluster not healthy after ${timeout}s (last: $snapshot)"
    return 1
}

# Everything that must survive the upgrade, one value per line.
snapshot_identity() {
    local out="$1"
    {
        echo "cluster.uid=$(kubectl get garagecluster garage -n "$NAMESPACE" -o jsonpath='{.metadata.uid}')"
        echo "bucket.id=$(kubectl get garagebucket upgrade-canary -n "$NAMESPACE" -o jsonpath='{.status.bucketId}')"
        echo "key.id=$(kubectl get garagekey upgrade-canary-key -n "$NAMESPACE" -o jsonpath='{.status.accessKeyId}')"
        echo "key.secret.sha=$(kubectl get secret upgrade-canary-credentials -n "$NAMESPACE" -o jsonpath='{.data}' | sha256sum | cut -d' ' -f1)"
        echo "admin.secret.sha=$(kubectl get secret garage-admin-token -n "$NAMESPACE" -o jsonpath='{.data.admin-token}' | sha256sum | cut -d' ' -f1)"
        echo "layout.roles=$(layout_roles)"
    } >"$out"
}

# Sorted "id zone capacity" for every committed role (data placement).
layout_roles() {
    kubectl exec upgrade-probe -n "$NAMESPACE" -- sh -c \
        "curl -fsS --max-time 10 -H \"Authorization: Bearer \$ADMIN_TOKEN\" $ADMIN_URL/v2/GetClusterLayout" >"$WORK_DIR/layout.json"
    python3 - "$WORK_DIR/layout.json" <<'PY'
import json, sys
layout = json.load(open(sys.argv[1]))
roles = sorted("%s/%s/%s" % (r["id"][:16], r["zone"], r.get("capacity")) for r in layout["roles"])
print(",".join(roles) + " staged=%d" % len(layout.get("stagedRoleChanges") or []))
PY
}

layout_version() {
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$WORK_DIR/layout.json"
}

garage_pod_uids() {
    kubectl get pods -n "$NAMESPACE" -l garage.rajsingh.info/cluster=garage \
        -o jsonpath='{range .items[*]}{.metadata.name}={.metadata.uid}{"\n"}{end}' | sort
}

start_probe() {
    kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: upgrade-probe
  namespace: ${NAMESPACE}
spec:
  restartPolicy: Never
  containers:
    - name: probe
      image: ${CURL_IMAGE}
      env:
        - name: AK
          valueFrom: {secretKeyRef: {name: upgrade-canary-credentials, key: access-key-id}}
        - name: SK
          valueFrom: {secretKeyRef: {name: upgrade-canary-credentials, key: secret-access-key}}
        - name: ADMIN_TOKEN
          valueFrom: {secretKeyRef: {name: garage-admin-token, key: admin-token}}
      command: ["sh", "-c", "sleep infinity"]
YAML
    kubectl wait --for=condition=Ready pod/upgrade-probe -n "$NAMESPACE" --timeout=180s >/dev/null
}

s3_put_canary() {
    kubectl exec upgrade-probe -n "$NAMESPACE" -- sh -c \
        "curl -fsS --max-time 15 --aws-sigv4 aws:amz:garage:s3 --user \"\$AK:\$SK\" -X PUT -H 'Content-Type: text/plain' --data-binary \"\$1\" $S3_URL/upgrade-canary/canary.txt" \
        sh "$CANARY_BODY" >/dev/null
}

s3_get_canary() {
    kubectl exec upgrade-probe -n "$NAMESPACE" -- sh -c \
        "curl -fsS --max-time 15 --aws-sigv4 aws:amz:garage:s3 --user \"\$AK:\$SK\" $S3_URL/upgrade-canary/canary.txt"
}

# The availability loop runs inside the probe Pod so it does not depend on a
# port-forward to a Pod the upgrade might replace. One line per second:
# "<epoch> s3=<code> health=<code>".
start_availability_loop() {
    kubectl exec -i upgrade-probe -n "$NAMESPACE" -- sh -c "cat > /tmp/loop.sh" <<'SH'
expect="$1"
while [ ! -f /tmp/stop ]; do
  ts=$(date +%s)
  code=$(curl -s -o /tmp/body -w '%{http_code}' --max-time 4 --aws-sigv4 aws:amz:garage:s3 --user "$AK:$SK" "$2/upgrade-canary/canary.txt")
  if [ "$code" = 200 ] && [ "$(cat /tmp/body)" != "$expect" ]; then code=corrupt; fi
  health=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "$3/health")
  echo "$ts s3=$code health=$health" >> /tmp/availability.log
  sleep 1
done
SH
    kubectl exec upgrade-probe -n "$NAMESPACE" -- sh -c \
        "nohup sh /tmp/loop.sh \"\$1\" $S3_URL $ADMIN_URL >/dev/null 2>&1 &" sh "$CANARY_BODY"
}

stop_availability_loop() {
    kubectl exec upgrade-probe -n "$NAMESPACE" -- sh -c "touch /tmp/stop; sleep 2; cat /tmp/availability.log" >"$WORK_DIR/availability.txt"
}

main() {
    cd "$ROOT_DIR"
    log_info "=== Upgrade E2E: released chart ${FROM_VERSION} -> this checkout ==="

    if ! kind_cluster_is_absent "$CLUSTER_NAME"; then
        log_error "Refusing to reuse pre-existing kind cluster '$CLUSTER_NAME'"
        exit 1
    fi
    local attempt
    for attempt in 1 2 3; do
        if kind create cluster --name "$CLUSTER_NAME" --image "$KIND_NODE_IMAGE" --wait 90s; then
            CLUSTER_CREATED=true
            CLUSTER_UID=$(kind_cluster_uid "$CLUSTER_NAME" || true)
            [ -n "$CLUSTER_UID" ] || { log_error "Could not record ownership of '$CLUSTER_NAME'"; exit 1; }
            break
        fi
        if ! kind_cluster_is_absent "$CLUSTER_NAME"; then
            log_error "kind create failed and left a cluster named '$CLUSTER_NAME'; refusing to continue"
            exit 1
        fi
        log_warn "kind create failed (attempt ${attempt}/3); retrying"
        sleep 10
    done
    [ "$CLUSTER_CREATED" = true ] || { log_error "kind create cluster failed"; exit 1; }

    # Build the PR image first so a build failure does not waste the install.
    if [ "$SKIP_BUILD" = false ]; then
        log_info "=== Building PR operator image ==="
        docker build -t garage-operator:e2e .
    fi
    kind load docker-image garage-operator:e2e --name "$CLUSTER_NAME"

    log_info "=== Installing cert-manager ==="
    "$ROOT_DIR/hack/install-cert-manager.sh"

    log_info "=== Installing released chart ${FROM_VERSION} ==="
    helm pull "$CHART_REF" --version "$FROM_VERSION" --untar -d "$WORK_DIR/chart"
    # The released chart's own e2e values (Kind-friendly security contexts),
    # but with its published image instead of the local e2e tag.
    helm install garage-operator "$WORK_DIR/chart/garage-operator" \
        --namespace "$NAMESPACE" --create-namespace \
        -f "$WORK_DIR/chart/garage-operator/values-e2e.yaml" \
        --set image.repository=ghcr.io/rajsinghtech/garage-operator \
        --set image.tag="v${FROM_VERSION}" \
        --set image.pullPolicy=IfNotPresent \
        --wait --timeout 300s
    NAMESPACE="$NAMESPACE" "$ROOT_DIR/hack/wait-for-operator-webhook.sh" "kind-$CLUSTER_NAME"
    kubectl get deployment garage-operator -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'

    log_info "=== Creating live resources with the released operator ==="
    kubectl apply -f hack/e2e-upgrade-resources.yaml
    wait_for_cluster_healthy 600
    wait_for_condition garagebucket upgrade-canary 300
    wait_for_condition garagekey upgrade-canary-key 300

    start_probe
    s3_put_canary
    [ "$(s3_get_canary)" = "$CANARY_BODY" ] || { log_error "canary object did not read back before the upgrade"; exit 1; }
    snapshot_identity "$WORK_DIR/before.txt"
    local version_before pods_before
    version_before=$(layout_version)
    pods_before=$(garage_pod_uids)
    log_info "Pre-upgrade identity:"
    cat "$WORK_DIR/before.txt"

    log_info "=== Upgrading to the PR build ==="
    start_availability_loop
    sleep 5
    helm upgrade garage-operator charts/garage-operator \
        --namespace "$NAMESPACE" \
        -f charts/garage-operator/values-e2e.yaml \
        --wait --timeout 300s
    kubectl rollout status deployment/garage-operator -n "$NAMESPACE" --timeout=180s
    NAMESPACE="$NAMESPACE" "$ROOT_DIR/hack/wait-for-operator-webhook.sh" "kind-$CLUSTER_NAME"
    local image
    image=$(kubectl get deployment garage-operator -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].image}')
    [ "$image" = "garage-operator:e2e" ] || fail "operator Deployment runs $image after the upgrade, want garage-operator:e2e"

    # Give the new operator several full reconcile passes over the live
    # resources before judging the end state.
    log_info "Letting the upgraded operator reconcile for 90s"
    sleep 90
    wait_for_cluster_healthy 600 || fail "GarageCluster did not return to healthy after the upgrade"
    wait_for_condition garagebucket upgrade-canary 300 || fail "GarageBucket not Ready after the upgrade"
    wait_for_condition garagekey upgrade-canary-key 300 || fail "GarageKey not Ready after the upgrade"
    stop_availability_loop

    log_info "=== Verifying no state loss ==="
    snapshot_identity "$WORK_DIR/after.txt"
    if ! diff -u "$WORK_DIR/before.txt" "$WORK_DIR/after.txt"; then
        fail "resource identity or layout roles changed across the upgrade"
    fi
    log_info "Layout version: $version_before -> $(layout_version)"
    [ "$(s3_get_canary)" = "$CANARY_BODY" ] || fail "canary object changed or is unreadable after the upgrade"

    # #474: upgrading records a redundancy baseline and starts no repairs.
    log_info "=== Verifying the upgrade started no redundancy repairs ==="
    local redundancy
    redundancy=$(kubectl get garagecluster garage -n "$NAMESPACE" \
        -o 'jsonpath={.status.redundancy.verification.phase}|{.status.redundancy.verification.trigger}|{.status.conditions[?(@.type=="FullyReplicated")].reason}')
    log_info "Redundancy after the upgrade (phase|trigger|reason): $redundancy"
    [ "$redundancy" = "Idle||NotVerified" ] || fail "the upgrade started a redundancy proof or did not record a baseline: $redundancy"

    log_info "=== Verifying no disruption ==="
    local pods_after rolled=false samples failures max_run
    pods_after=$(garage_pod_uids)
    if [ "$pods_before" != "$pods_after" ]; then
        rolled=true
        log_warn "The upgrade replaced Garage pods:"
        diff <(echo "$pods_before") <(echo "$pods_after") || true
    fi
    read -r samples failures max_run < <(awk '
        { n++; bad = ($2 != "s3=200" || $3 != "health=200") }
        bad { f++; run++; if (run > max) max = run; next }
        { run = 0 }
        END { printf "%d %d %d\n", n, f, max }' "$WORK_DIR/availability.txt")
    log_info "Availability: ${samples} samples, ${failures} failed, longest outage ${max_run}s"
    grep -vE 's3=200 health=200$' "$WORK_DIR/availability.txt" | head -20 || true
    if [ "$samples" -lt 60 ]; then
        fail "availability probe produced only ${samples} samples"
    fi
    if grep -q 's3=corrupt' "$WORK_DIR/availability.txt"; then
        fail "the canary object read back with different content during the upgrade"
    fi
    if [ "$rolled" = false ] && [ "$failures" -gt 0 ]; then
        fail "S3 or Garage health failed ${failures} time(s) although no Garage pod was replaced"
    elif [ "$max_run" -gt 3 ]; then
        fail "S3 or Garage health was unavailable for ${max_run}s in a row during the upgrade"
    fi

    log_info "=== Verifying the upgraded operator still provisions ==="
    kubectl apply -f - <<YAML
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageBucket
metadata:
  name: post-upgrade
  namespace: ${NAMESPACE}
spec:
  clusterRef:
    name: garage
  globalAlias: post-upgrade
---
apiVersion: garage.rajsingh.info/v1beta1
kind: GarageKey
metadata:
  name: post-upgrade-key
  namespace: ${NAMESPACE}
spec:
  clusterRef:
    name: garage
  bucketPermissions:
    - bucketRef:
        name: post-upgrade
      read: true
      write: true
  secretTemplate:
    name: post-upgrade-credentials
YAML
    if wait_for_condition garagebucket post-upgrade 300 && wait_for_condition garagekey post-upgrade-key 300; then
        local ak sk
        ak=$(kubectl get secret post-upgrade-credentials -n "$NAMESPACE" -o jsonpath='{.data.access-key-id}' | base64 -d)
        sk=$(kubectl get secret post-upgrade-credentials -n "$NAMESPACE" -o jsonpath='{.data.secret-access-key}' | base64 -d)
        if ! kubectl exec upgrade-probe -n "$NAMESPACE" -- sh -c \
            "curl -fsS --max-time 15 --aws-sigv4 aws:amz:garage:s3 --user \"\$1:\$2\" -X PUT -H 'Content-Type: text/plain' --data-binary ok $S3_URL/post-upgrade/x && curl -fsS --max-time 15 --aws-sigv4 aws:amz:garage:s3 --user \"\$1:\$2\" $S3_URL/post-upgrade/x" \
            sh "$ak" "$sk" | grep -qx ok; then
            fail "a key provisioned after the upgrade cannot write and read its bucket"
        fi
    else
        fail "the upgraded operator did not provision a new bucket and key"
    fi

    if kubectl logs deployment/garage-operator -n "$NAMESPACE" --tail=-1 | grep -E '^panic:|goroutine [0-9]+ \[running\]' >/dev/null; then
        fail "the upgraded operator logged a panic"
    fi
    local restarts
    restarts=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=garage-operator -o jsonpath='{range .items[*]}{.status.containerStatuses[0].restartCount}{"\n"}{end}' | awk '{s+=$1} END {print s+0}')
    [ "$restarts" = "0" ] || fail "the upgraded operator container restarted ${restarts} time(s)"

    if [ "$FAILURES" -gt 0 ]; then
        log_error "Upgrade E2E failed with ${FAILURES} failure(s)"
        exit 1
    fi
    log_info "Upgrade E2E passed: ${FROM_VERSION} -> PR build with no disruption or state loss"
}

main "$@"
