#!/usr/bin/env bash
#
# Install cert-manager into the current kubectl context (or a specific
# context if $1 is given) and block until the webhook is Available.
#
# The Helm chart's webhook stack (Certificate, Issuer, MutatingWebhook,
# ValidatingWebhook) defaults to webhooks.enabled: true since v0.5.1, so
# the e2e flow must install cert-manager before `helm install` or the
# install fails with `no matches for kind "Certificate" in version
# "cert-manager.io/v1"`.
#
# Version is pinned to match test/utils/utils.go:certmanagerVersion so
# the Ginkgo suites and the shell suites pull the same bundle.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=hack/e2e-common.sh
source "$SCRIPT_DIR/e2e-common.sh"

CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.19.1}"
CERT_MANAGER_SHA256="${CERT_MANAGER_SHA256:-876a41a57e36b85619f4124b24b3deb80912b5ffed515f90e2f160b6e6338e81}"
CONTEXT_ARG=()
if [ $# -ge 1 ] && [ -n "$1" ]; then
    CONTEXT_ARG=(--context "$1")
fi

URL="https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"
MANIFEST="$(mktemp)"
PINNED_MANIFEST="$(mktemp)"
trap 'rm -f "$MANIFEST" "$PINNED_MANIFEST"' EXIT

curl --fail --silent --show-error --location "$URL" --output "$MANIFEST"
printf '%s  %s\n' "$CERT_MANAGER_SHA256" "$MANIFEST" | sha256sum --check
"$SCRIPT_DIR/pin-manifest-images.sh" \
    "quay.io/jetstack/cert-manager-controller:v1.19.1=quay.io/jetstack/cert-manager-controller:v1.19.1@sha256:cd49e769e18ada1fd7b9a9bacc87c90db24c65cbfd4bf71694dda7ed40e91187" \
    "quay.io/jetstack/cert-manager-cainjector:v1.19.1=quay.io/jetstack/cert-manager-cainjector:v1.19.1@sha256:c7898aece8fb08102fca0b37683e37cb94e0a77c0d15b8e3c9128f6c04c868e0" \
    "quay.io/jetstack/cert-manager-webhook:v1.19.1=quay.io/jetstack/cert-manager-webhook:v1.19.1@sha256:f5bfe77541e38978aec53cc6eb924d190e1fe923c98b2582e6ccf5edf6c02cce" \
    "quay.io/jetstack/cert-manager-acmesolver:v1.19.1=quay.io/jetstack/cert-manager-acmesolver:v1.19.1@sha256:35ed1103cb49a3e1fc2438de84f304e3fbdeb53e0366f6b1bc2ec9b2e57462db" \
    < "$MANIFEST" > "$PINNED_MANIFEST"
kubectl "${CONTEXT_ARG[@]}" apply -f "$PINNED_MANIFEST"

# cainjector is what writes caBundle into our MutatingWebhookConfiguration; if
# it isn't running, the API server has no cert pinning for the operator
# webhook and admission calls fail with TLS errors.
for deploy in cert-manager cert-manager-cainjector cert-manager-webhook; do
    kubectl "${CONTEXT_ARG[@]}" wait "deployment.apps/${deploy}" \
        --for condition=Available \
        --namespace cert-manager \
        --timeout 5m
done
