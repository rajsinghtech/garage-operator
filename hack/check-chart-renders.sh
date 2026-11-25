#!/usr/bin/env bash

# Render the Helm chart across a matrix of values and validate every object
# with kubeconform in strict mode, including the Prometheus Operator,
# cert-manager and Gateway API custom resources the chart emits. Unknown or
# misspelled fields fail here instead of being pruned (or rejected) by the API
# server after a release ships.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

CHART_DIR="${HELM_CHART_DIR:-charts/garage-operator}"
KUBECONFORM="${KUBECONFORM:-kubeconform}"
# Pinned so a catalog update cannot change the result of an unchanged chart.
CRDS_CATALOG_REF="${CRDS_CATALOG_REF:-04af58d740718c4dc719441bf39fb284c784f4a8}"
CRDS_CATALOG="https://raw.githubusercontent.com/datreeio/CRDs-catalog/${CRDS_CATALOG_REF}/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"
# The chart's minimum (Chart.yaml kubeVersion) and a current release.
read -r -a KUBE_VERSIONS <<<"${KUBE_VERSIONS:-1.25.0 1.33.0}"

command -v helm >/dev/null || { echo "helm not found in PATH" >&2; exit 1; }
command -v "$KUBECONFORM" >/dev/null || { echo "$KUBECONFORM not found in PATH" >&2; exit 1; }

workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT

all_rules=()
for rule in GarageNodeDown GarageHighRPCErrorRate GarageBlockResyncErrors \
    GarageHighBlockResyncQueue GarageLowDiskSpace GarageBucketSizeQuotaNearLimit \
    GarageBucketObjectQuotaNearLimit GarageClusterUnhealthy GarageClusterUnavailable \
    GarageStorageNodeDown GaragePartitionsDegraded GarageNodeDisconnected; do
    all_rules+=(--set "prometheusRules.customRules.${rule}.for=7m")
done

# name|helm args (word-split; keep values free of spaces)
cases=(
    "defaults|"
    "values-dev|-f ${CHART_DIR}/values-dev.yaml"
    "values-e2e|-f ${CHART_DIR}/values-e2e.yaml"
    "values-e2e-webhooks|-f ${CHART_DIR}/values-e2e-webhooks.yaml"
    "values-cosi-e2e|-f ${CHART_DIR}/values-cosi-e2e.yaml"
    "all-features|--set serviceMonitor.enabled=true --set prometheusRules.enabled=true --set grafanaDashboard.enabled=true --set networkPolicy.enabled=true --set cosi.enabled=true --set gatewayAPI.enabled=true --set ingress.enabled=true --set replication.enabled=true --set prometheusRules.keepFiringFor=10m --set prometheusRules.additionalRuleLabels.team=storage --set prometheusRules.additionalRuleAnnotations.runbook_url=https://example.invalid --set prometheusRules.additionalRuleGroupLabels.cluster.tier=one --set prometheusRules.additionalRuleGroupAnnotations.quota.note=two --set prometheusRules.customRules.GarageNodeDown.severity=warning --set serviceMonitor.honorLabels=true --set serviceMonitor.jobLabel=app --set serviceMonitor.targetLabels[0]=app --set serviceMonitor.relabelings[0].action=keep --set serviceMonitor.relabelings[0].sourceLabels[0]=__name__ --set serviceMonitor.relabelings[0].regex=.+"
    "rules-overridden|--set prometheusRules.enabled=true ${all_rules[*]}"
    "podmonitor|--set podMonitor.enabled=true --set podMonitor.honorLabels=true --set podMonitor.authorization.type=Bearer --set podMonitor.authorization.credentials.name=metrics-token --set podMonitor.authorization.credentials.key=token --set podMonitor.metricRelabelings[0].action=drop --set podMonitor.metricRelabelings[0].sourceLabels[0]=__name__ --set podMonitor.metricRelabelings[0].regex=go_.*"
    "scoped|--set watchNamespaces={app,team-b} --set cosi.enabled=true --set cosi.namespace=shadows --set networkPolicy.enabled=true --set serviceMonitor.enabled=true --set replication.enabled=true --set ingress.enabled=true --set gatewayAPI.enabled=true"
    "scoped-any|--set watchNamespaces={app} --set watchAnyNamespace=true"
    "webhooks-off|--set webhooks.enabled=false"
    "external-certs|--set webhooks.certManager.enabled=false"
    "cluster-issuer|--set webhooks.certManager.issuerKind=ClusterIssuer --set webhooks.certManager.issuerName=letsencrypt"
    "no-rbac-no-sa|--set rbac.create=false --set serviceAccount.create=false --set serviceAccount.name=external"
    "scheduling|--set replicaCount=2 --set priorityClassName=system-cluster-critical --set nodeSelector.kubernetes\\.io/os=linux --set tolerations[0].operator=Exists --set topologySpreadConstraints[0].maxSkew=1 --set topologySpreadConstraints[0].topologyKey=kubernetes.io/hostname --set topologySpreadConstraints[0].whenUnsatisfiable=ScheduleAnyway --set-string image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --set imagePullSecrets[0].name=regcred --set fullnameOverride=go"
    "metrics-off|--set metrics.enabled=false --set prometheusRules.enabled=true"
    "crds-off|--set crds.install=false"
)

failed=0
for entry in "${cases[@]}"; do
    name="${entry%%|*}"
    args="${entry#*|}"
    out="$workdir/${name}.yaml"
    # shellcheck disable=SC2086 # args is an intentionally word-split flag list
    if ! helm template check "$CHART_DIR" --namespace garage-operator-system $args > "$out"; then
        echo "FAIL ${name}: helm template failed" >&2
        failed=1
        continue
    fi
    for kv in "${KUBE_VERSIONS[@]}"; do
        if ! "$KUBECONFORM" -strict -summary \
            -kubernetes-version "$kv" \
            -schema-location default \
            -schema-location "$CRDS_CATALOG" \
            -skip CustomResourceDefinition \
            "$out" | sed "s|^|[${name} k8s ${kv}] |"; then
            failed=1
        fi
    done
done

if [[ "$failed" -ne 0 ]]; then
    echo "chart render validation failed" >&2
    exit 1
fi
echo "all chart renders valid"
