#!/bin/bash
set -euo pipefail

# Cleanup script for garage-operator test clusters
# Usage: ./hack/cleanup-test.sh [cluster-name]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=hack/e2e-common.sh
source "$SCRIPT_DIR/e2e-common.sh"

CLUSTER_NAME="${1:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [ -n "$CLUSTER_NAME" ]; then
    # Delete specific cluster
    if ! clusters=$(kind get clusters 2>/dev/null); then
        log_error "Could not enumerate Kind clusters; refusing cleanup"
        exit 1
    fi
    if ! grep -Fqx -- "$CLUSTER_NAME" <<<"$clusters"; then
        log_info "Kind cluster '$CLUSTER_NAME' is already absent"
        exit 0
    fi
    log_info "Deleting kind cluster: $CLUSTER_NAME"
    kind delete cluster --name "$CLUSTER_NAME"
    if ! kind_cluster_is_absent "$CLUSTER_NAME"; then
        log_error "Could not verify deletion of Kind cluster '$CLUSTER_NAME'"
        exit 1
    fi
else
    # List and optionally delete all garage-related clusters
    if ! all_clusters=$(kind get clusters 2>/dev/null); then
        log_error "Could not enumerate Kind clusters; refusing cleanup"
        exit 1
    fi
    clusters=$(grep -E "^garage" <<<"$all_clusters" || true)

    if [ -z "$clusters" ]; then
        log_info "No garage-related kind clusters found"
        exit 0
    fi

    echo "Found garage-related clusters:"
    echo "$clusters"
    echo ""
    read -p "Delete all these clusters? [y/N] " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cleanup_status=0
        for cluster in $clusters; do
            log_info "Deleting: $cluster"
            if ! kind delete cluster --name "$cluster"; then
                log_error "Failed to delete Kind cluster '$cluster'"
                cleanup_status=1
                continue
            fi
            if ! kind_cluster_is_absent "$cluster"; then
                log_error "Could not verify deletion of Kind cluster '$cluster'"
                cleanup_status=1
            fi
        done
        if [ "$cleanup_status" -ne 0 ]; then
            exit "$cleanup_status"
        fi
        log_info "All clusters deleted"
    else
        log_info "Cancelled"
    fi
fi
