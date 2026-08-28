#!/usr/bin/env bash
#
# Wait until the garage-operator admission/conversion webhook is reachable
# in the current kubectl context (or the context passed as $1).
#
# Optional arguments are: kubectl context, Service name, namespace, timeout in
# seconds. The timeout applies to the entire helper, including the
# port-forward startup and probe.
# `helm install --wait` only blocks until the Deployment becomes Available,
# which fires as soon as the pod's readiness probe (port 8081 /readyz)
# returns 200. The Service endpoint slice and kube-proxy iptables for the
# webhook port (9443) can lag the pod-Ready event by a second or two — long
# enough for the first kubectl apply of a GarageCluster to land while the
# webhook Service still routes to nowhere, producing:
#   conversion webhook ... dial tcp ...:443: connect: connection refused
#
# This helper polls the webhook Service endpoint slice until it has stable
# Ready addresses, then probes the Service route and webhook server listener
# before the first admission request.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=hack/e2e-common.sh
source "$SCRIPT_DIR/e2e-common.sh"

NAMESPACE="${NAMESPACE:-garage-operator-system}"
# The shell E2E drivers install the chart as the `garage-operator` Helm
# release. Kustomize uses `garage-operator-webhook-service`; callers using that
# deployment must pass the Service explicitly as the optional second argument.
SERVICE="${SERVICE:-garage-operator-webhook}"
TIMEOUT="${TIMEOUT:-120}"
STABLE_POLLS="${STABLE_POLLS:-3}"

CONTEXT_ARG=()
if [ $# -ge 1 ] && [ -n "$1" ]; then
    CONTEXT_ARG=(--context "$1")
fi
if [ $# -ge 2 ] && [ -n "$2" ]; then
    SERVICE="$2"
fi
if [ $# -ge 3 ] && [ -n "$3" ]; then
    NAMESPACE="$3"
fi
if [ $# -ge 4 ] && [ -n "$4" ]; then
    TIMEOUT="$4"
fi

if ! [[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
    echo "webhook wait timeout must be a positive integer number of seconds: $TIMEOUT" >&2
    exit 2
fi

# shellcheck disable=SC2329 # invoked by the EXIT trap below
on_exit() {
    local status=$? cleanup_status=0
    trap - EXIT
    stop_all_port_forwards || cleanup_status=$?
    if [ "$status" -eq 0 ] && [ "$cleanup_status" -ne 0 ]; then
        status=$cleanup_status
    fi
    exit "$status"
}
trap on_exit EXIT

wait_for_webhook_route() {
    local context=""
    if [ "${#CONTEXT_ARG[@]}" -eq 2 ]; then
        context="${CONTEXT_ARG[1]}"
    fi

    local remaining
    remaining=$((deadline - SECONDS))
    if [ "$remaining" -lt 1 ]; then
        return 1
    fi
    if ! start_port_forward "service/$SERVICE" 443 "$NAMESPACE" "$remaining" "$context"; then
        return 1
    fi

    local pid=$PORT_FORWARD_PID
    local forwarded_port=$PORT_FORWARD_PORT
    local log_file=$PORT_FORWARD_LOG
    remaining=$((deadline - SECONDS))
    if [ "$remaining" -ge 1 ] && wait_for_port_forward "$pid" \
        "https://127.0.0.1:$forwarded_port/" "$remaining" "$log_file"; then
        stop_port_forward "$pid" "$log_file"
        return 0
    fi
    stop_port_forward "$pid" "$log_file" || true
    return 1
}

deadline=$((SECONDS + TIMEOUT))
last_addrs=""
stable_count=0
while [ "$SECONDS" -lt "$deadline" ]; do
    remaining=$((deadline - SECONDS))
    request_timeout=5
    if [ "$remaining" -lt "$request_timeout" ]; then
        request_timeout="$remaining"
    fi
    if [ "$request_timeout" -lt 1 ]; then
        break
    fi
    addrs=$(kubectl "${CONTEXT_ARG[@]}" get endpointslice \
        -n "$NAMESPACE" \
        -l "kubernetes.io/service-name=$SERVICE" \
        -o json \
        "--request-timeout=${request_timeout}s" \
        2>/dev/null | jq -r '
            [.items[]?.endpoints[]?
                | select(.conditions.ready == true)
                | select(.conditions.serving != false)
                | select(.conditions.terminating != true)
                | .addresses[]?]
            | unique[]?
        ' | paste -sd' ' - || true)
    if [ -n "$addrs" ] && [ "$addrs" != " " ]; then
        if [ "$addrs" = "$last_addrs" ]; then
            stable_count=$((stable_count + 1))
        else
            last_addrs="$addrs"
            stable_count=1
        fi

        if [ "$stable_count" -ge "$STABLE_POLLS" ]; then
            if wait_for_webhook_route; then
                echo "garage-operator webhook endpoints and Service route are ready: $addrs"
                exit 0
            fi
            last_addrs=""
            stable_count=0
        fi
    else
        last_addrs=""
        stable_count=0
    fi
    remaining=$((deadline - SECONDS))
    if [ "$remaining" -gt 0 ]; then
        sleep "$((remaining < 2 ? remaining : 2))"
    fi
done

echo "timed out waiting for $SERVICE endpoints in $NAMESPACE" >&2
kubectl "${CONTEXT_ARG[@]}" get pods -n "$NAMESPACE" >&2 || true
kubectl "${CONTEXT_ARG[@]}" get endpointslice -n "$NAMESPACE" -l "kubernetes.io/service-name=$SERVICE" -o yaml >&2 || true
exit 1
