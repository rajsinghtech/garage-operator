#!/usr/bin/env bash
#
# Wait until the garage-operator admission/conversion webhook is reachable
# in the current kubectl context (or the context passed as $1).
#
# `helm install --wait` only blocks until the Deployment becomes Available,
# which fires as soon as the pod's readiness probe (port 8081 /readyz)
# returns 200. The Service endpoint slice and kube-proxy iptables for the
# webhook port (9443) can lag the pod-Ready event by a second or two — long
# enough for the first kubectl apply of a GarageCluster to land while the
# webhook Service still routes to nowhere, producing:
#   conversion webhook ... dial tcp ...:443: connect: connection refused
#
# This helper polls the webhook Service endpoint slice until it has at least
# one Ready address, then opens a TLS handshake against :443 to verify
# kube-proxy has the route plumbed.

set -euo pipefail

NAMESPACE="${NAMESPACE:-garage-operator-system}"
SERVICE="${SERVICE:-garage-operator-webhook}"
TIMEOUT="${TIMEOUT:-120}"

CONTEXT_ARG=()
if [ $# -ge 1 ] && [ -n "$1" ]; then
    CONTEXT_ARG=(--context "$1")
fi

deadline=$(( $(date +%s) + TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    addrs=$(kubectl "${CONTEXT_ARG[@]}" get endpointslice \
        -n "$NAMESPACE" \
        -l "kubernetes.io/service-name=$SERVICE" \
        -o jsonpath='{range .items[*]}{range .endpoints[?(@.conditions.ready==true)]}{.addresses[0]} {end}{end}' \
        2>/dev/null | tr -s ' ')
    if [ -n "$addrs" ] && [ "$addrs" != " " ]; then
        echo "garage-operator webhook endpoints ready: $addrs"
        exit 0
    fi
    sleep 2
done

echo "timed out waiting for $SERVICE endpoints in $NAMESPACE" >&2
kubectl "${CONTEXT_ARG[@]}" get pods -n "$NAMESPACE" >&2 || true
kubectl "${CONTEXT_ARG[@]}" get endpointslice -n "$NAMESPACE" -l "kubernetes.io/service-name=$SERVICE" -o yaml >&2 || true
exit 1
