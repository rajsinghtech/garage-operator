#!/bin/bash

# Shared synchronization helpers for the shell E2E drivers. These functions
# only consider a port-forward ready after the endpoint answers, and only kill
# the exact child process that the caller started.
# wait_for_port_forward's optional fifth argument is "success" for a 2xx-only
# probe or "any-response" for endpoints where a 4xx proves reachability (such
# as unauthenticated S3). With no fifth argument, health/healthz URLs use the
# success policy and other URLs use any-response.

# The shell drivers issue a large number of one-shot Kubernetes API requests.
# A broken API connection must become a failed poll, not suspend the enclosing
# timeout forever. Commands that intentionally hold a stream (wait, rollout,
# and port-forward) keep their operation-specific lifetimes. Logs get a
# bounded Pod-start wait, and exec gets its API deadline before the child
# command separator.
kubectl() {
    local arg verb="" skip_next=false has_request_timeout=false
    local has_pod_running_timeout=false has_follow=false execution_timeout=""
    local -a kubectl_args=("$@")

    for arg in "${kubectl_args[@]}"; do
        if [ "$arg" = "--" ]; then
            break
        fi
        if [ "$arg" = "--request-timeout" ] || [[ "$arg" == --request-timeout=* ]]; then
            has_request_timeout=true
        fi
        if [ "$arg" = "--pod-running-timeout" ] || [[ "$arg" == --pod-running-timeout=* ]]; then
            has_pod_running_timeout=true
        fi
        if [ "$arg" = "-f" ] || [ "$arg" = "--follow" ] || [ "$arg" = "--follow=true" ]; then
            has_follow=true
        fi
    done

    for arg in "${kubectl_args[@]}"; do
        if [ "$skip_next" = true ]; then
            skip_next=false
            continue
        fi
        case "$arg" in
            --context|--kubeconfig|--namespace|-n|--server|--as|--as-group|--as-user|--as-uid|--cluster|--user|--token|--certificate-authority|--client-certificate|--client-key|--cache-dir|--request-timeout|-f)
                skip_next=true
                continue
                ;;
            --context=*|--kubeconfig=*|--namespace=*|--server=*|--as=*|--as-group=*|--as-user=*|--as-uid=*|--cluster=*|--user=*|--token=*|--certificate-authority=*|--client-certificate=*|--client-key=*|--cache-dir=*|--request-timeout=*)
                continue
                ;;
            --)
                break
                ;;
            -*)
                continue
                ;;
            *)
                verb="$arg"
                break
                ;;
        esac
    done

    case "$verb" in
        get|apply|create|patch|label|annotate|delete|scale|api-resources|describe|cluster-info|kustomize)
            if [ "$has_request_timeout" = false ]; then
                kubectl_args+=("--request-timeout=${E2E_KUBECTL_REQUEST_TIMEOUT:-15s}")
            fi
            if [ "$verb" = kustomize ]; then
                execution_timeout="${E2E_KUBECTL_KUSTOMIZE_TIMEOUT:-5m}"
            fi
            ;;
        logs)
            if [ "$has_pod_running_timeout" = false ]; then
                kubectl_args+=("--pod-running-timeout=${E2E_KUBECTL_POD_RUNNING_TIMEOUT:-15s}")
            fi
            if [ "$has_follow" = false ] && [ "$has_request_timeout" = false ]; then
                kubectl_args+=("--request-timeout=${E2E_KUBECTL_REQUEST_TIMEOUT:-15s}")
            fi
            ;;
        exec|run)
            if [ "$has_request_timeout" = false ]; then
                local separator index
                separator="${#kubectl_args[@]}"
                for index in "${!kubectl_args[@]}"; do
                    if [ "${kubectl_args[$index]}" = "--" ]; then
                        separator="$index"
                        break
                    fi
                done
                if [ "$separator" -eq "${#kubectl_args[@]}" ]; then
                    kubectl_args+=("--request-timeout=${E2E_KUBECTL_REQUEST_TIMEOUT:-15s}")
                else
                    kubectl_args+=("")
                    for ((index = ${#kubectl_args[@]} - 1; index > separator; index--)); do
                        kubectl_args[index]="${kubectl_args[index - 1]}"
                    done
                    kubectl_args[separator]="--request-timeout=${E2E_KUBECTL_REQUEST_TIMEOUT:-15s}"
                fi
            fi
            ;;
    esac

    if [ -n "$execution_timeout" ]; then
        e2e_timeout "$execution_timeout" kubectl "${kubectl_args[@]}"
    else
        command kubectl "${kubectl_args[@]}"
    fi
}

# curl has no default deadline. Every E2E HTTP probe is a one-shot health or
# API request, so give it bounded connect and total times while allowing an
# explicit option in the caller to override these defaults (later arguments
# win in curl's option parser).
curl() {
    command curl \
        --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT:-5}" \
        --max-time "${E2E_CURL_MAX_TIME:-30}" \
        "$@"
}

# Kind and Docker talk to a daemon that can become unresponsive independently
# of the Kubernetes/API deadlines above. Keep those calls bounded too: a
# failed cleanup must return control to the EXIT trap instead of waiting for a
# dead Docker socket forever. The wrappers intentionally retain the command
# names used by the drivers, so a timeout covers existing call sites as well
# as new ones.
e2e_timeout() {
    local duration="$1"
    shift
    command timeout --foreground "$duration" "$@"
}

kind() {
    local duration
    case "${1:-}" in
        get)
            duration="${E2E_KIND_QUERY_TIMEOUT:-15s}"
            ;;
        create)
            duration="${E2E_KIND_CREATE_TIMEOUT:-5m}"
            ;;
        delete)
            duration="${E2E_KIND_DELETE_TIMEOUT:-5m}"
            ;;
        load)
            duration="${E2E_KIND_LOAD_TIMEOUT:-5m}"
            ;;
        *)
            duration="${E2E_KIND_DEFAULT_TIMEOUT:-2m}"
            ;;
    esac
    e2e_timeout "$duration" kind "$@"
}

docker() {
    local duration
    case "${1:-}" in
        build)
            duration="${E2E_DOCKER_BUILD_TIMEOUT:-15m}"
            ;;
        run)
            duration="${E2E_DOCKER_RUN_TIMEOUT:-5m}"
            ;;
        exec)
            duration="${E2E_DOCKER_EXEC_TIMEOUT:-60s}"
            ;;
        network)
            duration="${E2E_DOCKER_NETWORK_TIMEOUT:-60s}"
            ;;
        rm|stop|kill)
            duration="${E2E_DOCKER_CONTAINER_TIMEOUT:-2m}"
            ;;
        logs|inspect)
            duration="${E2E_DOCKER_QUERY_TIMEOUT:-30s}"
            ;;
        *)
            duration="${E2E_DOCKER_DEFAULT_TIMEOUT:-2m}"
            ;;
    esac
    e2e_timeout "$duration" docker "$@"
}

helm() {
    local duration
    case "${1:-}" in
        install|upgrade)
            duration="${E2E_HELM_INSTALL_TIMEOUT:-5m}"
            ;;
        uninstall)
            duration="${E2E_HELM_UNINSTALL_TIMEOUT:-3m}"
            ;;
        *)
            duration="${E2E_HELM_DEFAULT_TIMEOUT:-2m}"
            ;;
    esac
    e2e_timeout "$duration" helm "$@"
}

make() {
    local duration
    case "${1:-}" in
        docker-build)
            duration="${E2E_MAKE_BUILD_TIMEOUT:-15m}"
            ;;
        *)
            duration="${E2E_MAKE_TIMEOUT:-10m}"
            ;;
    esac
    e2e_timeout "$duration" make "$@"
}

# Return success only when Kind has positively reported that a cluster name is
# absent. A failed `kind get clusters` is deliberately treated as unsafe: the
# setup scripts must never mistake an unavailable Docker daemon for a free name
# and then attach to or overwrite an existing cluster.
kind_cluster_is_absent() {
    local cluster="$1"
    local clusters
    if ! clusters=$(kind get clusters 2>/dev/null); then
        return 1
    fi
    ! grep -Fqx -- "$cluster" <<<"$clusters"
}

kind_cluster_uid() {
    local cluster="$1"
    kubectl --context "kind-$cluster" get namespace kube-system \
        -o jsonpath='{.metadata.uid}' --request-timeout=10s 2>/dev/null
}

# Wait for one named Kubernetes object to disappear. API failures are
# retryable observations, not proof that the object is gone; callers use this
# barrier before deleting a parent namespace or moving on to another fixture.
# Arguments: resource, name, timeout, [namespace].
wait_for_resource_deleted() {
    local resource="$1"
    local name="$2"
    local timeout="$3"
    local namespace="${4:-${NAMESPACE:-}}"
    local end_time=$((SECONDS + timeout))
    local -a get_args=(get "$resource" "$name" --ignore-not-found -o name --request-timeout=5s)

    if [ -n "$namespace" ]; then
        get_args+=(-n "$namespace")
    fi

    while [ "$SECONDS" -lt "$end_time" ]; do
        local object
        if object=$(kubectl "${get_args[@]}" 2>/dev/null); then
            if [ -z "$object" ]; then
                return 0
            fi
        fi
        sleep 1
    done

    return 1
}

# start_port_forward starts a forward on an ephemeral local port and waits
# until kubectl has reported the allocation. The caller must still use
# wait_for_port_forward to prove that the service route and endpoint are
# usable. Results are returned through globals because command substitution
# would orphan the background kubectl process in a subshell:
#
#   PORT_FORWARD_PID, PORT_FORWARD_PORT, PORT_FORWARD_LOG
#
# Arguments: target, remote-port, namespace, startup-timeout, [context].
declare -Ag E2E_PORT_FORWARD_LOGS=()

start_port_forward() {
    local target="$1"
    local remote_port="$2"
    local namespace="$3"
    local timeout="${4:-30}"
    local context="${5:-}"
    local end_time
    local allocated_port
    local -a context_args=()

    PORT_FORWARD_PID=""
    PORT_FORWARD_PORT=""
    PORT_FORWARD_LOG=""

    if [ -n "$context" ]; then
        context_args=(--context "$context")
    fi
    if ! PORT_FORWARD_LOG=$(mktemp "${TMPDIR:-/tmp}/garage-port-forward.XXXXXX"); then
        return 1
    fi

    # Invoke the binary directly so $! is the kubectl process itself. Running
    # the shell kubectl wrapper in the background would make $! the wrapper's
    # subshell; killing that shell can leave the real port-forward orphaned.
    command kubectl "${context_args[@]}" port-forward --address 127.0.0.1 \
        "$target" ":$remote_port" -n "$namespace" \
        >"$PORT_FORWARD_LOG" 2>&1 &
    PORT_FORWARD_PID=$!
    E2E_PORT_FORWARD_LOGS["$PORT_FORWARD_PID"]="$PORT_FORWARD_LOG"
    end_time=$((SECONDS + timeout))

    while [ "$SECONDS" -lt "$end_time" ]; do
        if ! port_forward_is_running "$PORT_FORWARD_PID"; then
            cat "$PORT_FORWARD_LOG" >&2 || true
            stop_port_forward "$PORT_FORWARD_PID" "$PORT_FORWARD_LOG" || true
            return 1
        fi

        allocated_port=$(sed -nE \
            "s/.*Forwarding from 127\\.0\\.0\\.1:([0-9]+) -> ${remote_port}.*/\\1/p" \
            "$PORT_FORWARD_LOG" | head -n 1)
        if [[ "$allocated_port" =~ ^[0-9]+$ ]] && [ "$allocated_port" -gt 0 ]; then
            # shellcheck disable=SC2034 # consumed by the calling shell
            PORT_FORWARD_PORT="$allocated_port"
            return 0
        fi
        sleep 0.1
    done

    cat "$PORT_FORWARD_LOG" >&2 || true
    stop_port_forward "$PORT_FORWARD_PID" "$PORT_FORWARD_LOG" || true
    return 1
}

wait_for_port_forward() {
    local pid="$1"
    local probe_url="$2"
    local timeout="${3:-30}"
    local log_file="${4:-}"
    local probe_mode="${5:-auto}"
    local end_time=$((SECONDS + timeout))

    case "$probe_mode" in
        auto)
            case "$probe_url" in
                */health|*/healthz) probe_mode=success ;;
                *) probe_mode=any-response ;;
            esac
            ;;
        any-response|success) ;;
        *)
            echo "Unknown port-forward probe mode '$probe_mode'" >&2
            return 2
            ;;
    esac

    local -a curl_args=()
    case "$probe_url" in
        https://*) curl_args+=(--insecure) ;;
    esac

    while [ "$SECONDS" -lt "$end_time" ]; do
        # Check liveness before probing. Otherwise a stale listener on the
        # requested local port can make a newly-started, already-dead
        # port-forward look ready.
        if ! port_forward_is_running "$pid"; then
            if [ -n "$log_file" ] && [ -f "$log_file" ]; then
                cat "$log_file" >&2 || true
            fi
            return 1
        fi

        local http_code
        http_code=$(curl --silent --show-error --connect-timeout 1 --max-time 2 \
            "${curl_args[@]}" --output /dev/null --write-out '%{http_code}' \
            "$probe_url" 2>/dev/null || true)
        # A health endpoint is not ready when it returns 503. S3 probes use
        # any HTTP response because 403 is the expected unauthenticated
        # response and still proves that the forwarded service is reachable.
        if { [ "$probe_mode" = success ] && [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; } || \
            { [ "$probe_mode" = any-response ] && [[ "$http_code" =~ ^[1-5][0-9][0-9]$ ]]; }; then
            # Do not accept a response from a process that exited while curl
            # was running. This closes the common port-reuse race at both
            # sides of the probe.
            if ! port_forward_is_running "$pid"; then
                return 1
            fi
            return 0
        fi
        sleep 1
    done

    if [ -n "$log_file" ] && [ -f "$log_file" ]; then
        cat "$log_file" >&2 || true
    fi
    return 1
}

ready_active_pod_count() {
    local namespace="$1"
    local selector="$2"
    local context="${3:-}"
    local kubectl_context=()
    if [ -n "$context" ]; then
        kubectl_context=(--context "$context")
    fi

    kubectl "${kubectl_context[@]}" get pods -n "$namespace" -l "$selector" \
        -o json --request-timeout=5s 2>/dev/null |
        jq -r '
            [.items[]?
                | select(.metadata.deletionTimestamp == null)
                | select(.status.phase == "Running")
                | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))]
            | length
        '
}

stop_port_forward() {
    local pid="${1:-}"
    local log_file="${2:-}"
    local stopped=true
    local index
    if ! [[ "$pid" =~ ^[0-9]+$ ]]; then
        [ -z "$log_file" ] || rm -f -- "$log_file"
        return 0
    fi
    if port_forward_is_running "$pid"; then
        kill "$pid" 2>/dev/null || true
        for ((index = 0; index < 50; index++)); do
            if ! port_forward_is_running "$pid"; then
                break
            fi
            sleep 0.1
        done
        if port_forward_is_running "$pid"; then
            kill -KILL "$pid" 2>/dev/null || true
            for ((index = 0; index < 20; index++)); do
                if ! port_forward_is_running "$pid"; then
                    break
                fi
                sleep 0.1
            done
        fi
    fi
    if port_forward_is_running "$pid"; then
        stopped=false
        echo "Timed out stopping port-forward process $pid" >&2
    else
        wait "$pid" 2>/dev/null || true
    fi
    unset "E2E_PORT_FORWARD_LOGS[$pid]"
    [ -z "$log_file" ] || rm -f -- "$log_file"
    [ "$stopped" = true ]
}

stop_all_port_forwards() {
    local pid log_file cleanup_status=0
    for pid in "${!E2E_PORT_FORWARD_LOGS[@]}"; do
        log_file="${E2E_PORT_FORWARD_LOGS[$pid]}"
        if ! stop_port_forward "$pid" "$log_file"; then
            cleanup_status=1
        fi
    done
    return "$cleanup_status"
}

# kill -0 still succeeds for a child that has exited but has not yet been
# reaped. Treat a Linux zombie as stopped so cleanup reaches wait(2) instead
# of sleeping through both escalation windows and reporting a false leak.
port_forward_is_running() {
    local pid="$1"
    local process_state
    if ! [[ "$pid" =~ ^[0-9]+$ ]] || ! kill -0 "$pid" 2>/dev/null; then
        return 1
    fi
    process_state=$(ps -o stat= -p "$pid" 2>/dev/null || true)
    [[ "$process_state" != Z* ]]
}

pod_ip_for_selector() {
    local namespace="$1"
    local selector="$2"
    local context="${3:-}"
    local kubectl_context=()
    if [ -n "$context" ]; then
        kubectl_context=(--context "$context")
    fi

    kubectl "${kubectl_context[@]}" get pods -n "$namespace" -l "$selector" \
        -o json --request-timeout=5s 2>/dev/null |
        jq -r '
            def ready: any(.status.conditions[]?; .type == "Ready" and .status == "True");
            [.items[]?
                | select(.metadata.deletionTimestamp == null)
                | select(.status.phase == "Running")
                | select((.status.podIP // "") != "")]
            | sort_by(.metadata.name)
            | (map(select(ready)) + .)
            | first
            | .status.podIP // empty
        '
}

pod_name_for_selector() {
    local namespace="$1"
    local selector="$2"
    local context="${3:-}"
    local kubectl_context=()
    if [ -n "$context" ]; then
        kubectl_context=(--context "$context")
    fi

    kubectl "${kubectl_context[@]}" get pods -n "$namespace" -l "$selector" \
        -o json --request-timeout=5s 2>/dev/null |
        jq -r '
            def ready: any(.status.conditions[]?; .type == "Ready" and .status == "True");
            [.items[]?
                | select(.metadata.deletionTimestamp == null and (.metadata.name // "") != "")]
            | sort_by(.metadata.name)
            | (map(select(ready)) + .)
            | first
            | .metadata.name // empty
        '
}
