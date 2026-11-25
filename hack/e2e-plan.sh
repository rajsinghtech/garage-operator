#!/usr/bin/env bash
# Decide which E2E lanes and targeted jobs a workflow run needs and emit the
# Ginkgo shard matrix.
#
# Outputs (to $GITHUB_OUTPUT):
#   e2e=true|false              false only for pull requests that change docs alone
#   full=true|false             true runs the drain shards
#   arm64=true|false            true runs core-arm64 (push / run-full-e2e only)
#   cosi=true|false             run COSI E2E Tests
#   multicluster=true|false     run Multi-Cluster E2E Tests
#   external_gateway=true|false run External Gateway E2E Tests
#   upgrade=true|false          run Upgrade E2E Tests
#   ipv6=true|false             run IPv6 Dual-Stack E2E Tests
#   single_cluster=true|false   run Single-Cluster E2E Tests
#   matrix=<json>               {"shard":[...]} from .github/e2e-shards.json
set -euo pipefail

SHARDS_FILE="${SHARDS_FILE:-.github/e2e-shards.json}"
FULL_LABEL="run-full-e2e"

# Every changed path must match this for a PR to skip E2E entirely.
DOCS_ONLY_RE='^(docs/|.*\.md$|mkdocs\.yml$|LICENSE$|\.github/ISSUE_TEMPLATE/)'

# Any non-test path matching this forces the drain shards on a PR: controllers
# and Garage admin client behind drain/retirement/node lifecycle, the shared E2E
# harness, the CI wiring itself, and Go dependencies.
FULL_LANE_RE='^(internal/controller/(block_resync_barrier|garagecluster_block_resync_status|garagecluster_layout_barrier|layout_mutation_coordinator|layout_site_role|garagenode_controller|garagenode_cycle|garagecluster_automode[a-z_]*|garagecluster_scale_status|garagecluster_storage_daemonset|storage_rollout|statefulset_identity_handoff|automode_pvc_handoff|node_local_pool_[a-z_]+)\.go$|internal/garage/[a-z_]+\.go$|api/v1beta[12]/(garagenode[a-z_]*|garagecluster_scale_webhook)\.go$|test/e2e/(e2e_suite_test|e2e_test|e2e_waits)\.go$|test/utils/|hack/e2e-plan\.sh$|hack/check-e2e-shards\.py$|\.github/e2e-shards\.json$|\.github/workflows/test-e2e\.yml$|\.github/actions/load-e2e-image/|go\.(mod|sum)$)'

SHARED_INFRA_RE='^(cmd/|charts/|Dockerfile$|Makefile$|go\.(mod|sum)$|hack/e2e-common\.sh$|hack/e2e-plan\.sh$|\.github/workflows/test-e2e\.yml$|\.github/actions/load-e2e-image/)'
COSI_RE="(${SHARED_INFRA_RE}|^internal/cosi/|^hack/e2e-cosi\\.sh$)"
MULTICLUSTER_RE="(${SHARED_INFRA_RE}|^internal/controller/.*(federation|garagecluster)|^internal/garage/|^api/|^hack/e2e-multicluster\\.sh$)"
EXT_GW_RE="(${SHARED_INFRA_RE}|^internal/controller/|^internal/garage/|^api/|^test/e2e/|^hack/e2e-external-gateway\\.sh$)"
IPV6_RE="(${SHARED_INFRA_RE}|^internal/controller/|^internal/garage/|^api/|^hack/e2e-ipv6\\.sh$)"
UPGRADE_RE="(${SHARED_INFRA_RE}|^internal/|^api/|^config/|^hack/e2e-upgrade\\.sh$)"
SINGLE_CLUSTER_RE="(${SHARED_INFRA_RE}|^internal/|^api/|^config/|^hack/e2e-cluster\\.sh$)"

e2e=true
full=true
arm64=true
cosi=true
multicluster=true
external_gateway=true
upgrade=true
ipv6=true
single_cluster=true
reason="event ${EVENT_NAME}"

has_match() {
    local re="$1"
    grep -qE "$re" <<<"$files"
}

if [ "${EVENT_NAME}" = "pull_request" ]; then
    if [ -n "${LABELS_OVERRIDE+x}" ]; then
        labels="$LABELS_OVERRIDE"
    else
        : "${PR_NUMBER:?PR_NUMBER is required for pull_request events}"
        labels="$(gh api "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/labels" --paginate --jq '.[].name')"
    fi
    if [ -n "${CHANGED_FILES_OVERRIDE+x}" ]; then
        files="$CHANGED_FILES_OVERRIDE"
    else
        : "${PR_NUMBER:?PR_NUMBER is required for pull_request events}"
        files="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/files" --paginate --jq '.[].filename')"
    fi
    file_count="$(printf '%s\n' "$files" | sed '/^$/d' | wc -l)"

    if grep -qxF "$FULL_LABEL" <<<"$labels"; then
        reason="PR labelled ${FULL_LABEL}"
    elif [ "$file_count" -ge 3000 ]; then
        reason="PR changes >= 3000 files"
    elif [ "$file_count" -gt 0 ] && ! grep -qvE "$DOCS_ONLY_RE" <<<"$files"; then
        e2e=false
        full=false
        arm64=false
        cosi=false
        multicluster=false
        external_gateway=false
        upgrade=false
        ipv6=false
        single_cluster=false
        reason="PR changes docs only"
    else
        # core-arm64 runs on main/v* tags (or run-full-e2e label) only.
        arm64=false
        if hits="$(grep -E "$FULL_LANE_RE" <<<"$files" | grep -vE '^(internal|api)/.*_test\.go$')"; then
            reason="PR touches drain/node-lifecycle or E2E paths: $(head -5 <<<"$hits" | paste -sd ' ' -)"
        else
            full=false
            reason="PR fast lane (no drain/node-lifecycle paths; add ${FULL_LABEL} and re-run for the full matrix)"
        fi
        has_match "$COSI_RE" || cosi=false
        has_match "$MULTICLUSTER_RE" || multicluster=false
        has_match "$EXT_GW_RE" || external_gateway=false
        has_match "$IPV6_RE" || ipv6=false
        has_match "$UPGRADE_RE" || upgrade=false
        has_match "$SINGLE_CLUSTER_RE" || single_cluster=false
    fi
fi

if [ "$arm64" = true ]; then
    matrix="$(jq -c '{shard: [.shard[] | del(.lane)]}' "$SHARDS_FILE")"
elif [ "$full" = true ]; then
    matrix="$(jq -c '{shard: [.shard[] | select(.lane != "push") | del(.lane)]}' "$SHARDS_FILE")"
else
    matrix="$(jq -c '{shard: [.shard[] | select(.lane == "pr") | .filter = (if (.filter | test("!drain")) then .filter else "(" + .filter + ") && !drain" end) | del(.lane)]}' "$SHARDS_FILE")"
fi

lane=fast
if [ "$e2e" != true ]; then
    lane=skipped
elif [ "$arm64" = true ]; then
    lane="full+arm64"
elif [ "$full" = true ]; then
    lane=full
fi

echo "E2E plan: ${lane} lane, e2e=${e2e} full=${full} arm64=${arm64} cosi=${cosi} multicluster=${multicluster} external_gateway=${external_gateway} upgrade=${upgrade} ipv6=${ipv6} single_cluster=${single_cluster} (${reason})"
jq -r '.shard[] | "  \(.name): \(.filter)"' <<<"$matrix"
{
    echo "e2e=${e2e}"
    echo "full=${full}"
    echo "arm64=${arm64}"
    echo "cosi=${cosi}"
    echo "multicluster=${multicluster}"
    echo "external_gateway=${external_gateway}"
    echo "upgrade=${upgrade}"
    echo "ipv6=${ipv6}"
    echo "single_cluster=${single_cluster}"
    echo "matrix=${matrix}"
} >> "${GITHUB_OUTPUT:-/dev/stdout}"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo "E2E plan: **${lane}** lane — ${reason}" >> "$GITHUB_STEP_SUMMARY"
fi
