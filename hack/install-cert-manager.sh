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

CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.19.1}"
CONTEXT_ARG=()
if [ $# -ge 1 ] && [ -n "$1" ]; then
    CONTEXT_ARG=(--context "$1")
fi

URL="https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"

kubectl "${CONTEXT_ARG[@]}" apply -f "$URL"

# cainjector is what writes caBundle into our MutatingWebhookConfiguration; if
# it isn't running, the API server has no cert pinning for the operator
# webhook and admission calls fail with TLS errors.
for deploy in cert-manager cert-manager-cainjector cert-manager-webhook; do
    kubectl "${CONTEXT_ARG[@]}" wait "deployment.apps/${deploy}" \
        --for condition=Available \
        --namespace cert-manager \
        --timeout 5m
done
