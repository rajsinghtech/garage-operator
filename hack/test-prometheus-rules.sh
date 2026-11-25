#!/usr/bin/env bash

# Render the chart PrometheusRule, syntax-check it with promtool, and run the
# unit tests in charts/garage-operator/tests/prometheus-rules-test.yaml.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

CHART_DIR="${HELM_CHART_DIR:-charts/garage-operator}"
TEST_FILE="$CHART_DIR/tests/prometheus-rules-test.yaml"
LOCALBIN="${LOCALBIN:-$ROOT_DIR/bin}"
PROMTOOL="${PROMTOOL:-}"
PROMETHEUS_VERSION="${PROMETHEUS_VERSION:-3.16.0}"

# Official prometheus-3.16.0 release checksums (prometheus.io/download).
promtool_sha256() {
    case "$1" in
        linux-amd64)  echo 68727009472a2c02e1ff7f062fd5b3e637285bffc8fc2d340c76fb449d6e0f34 ;;
        linux-arm64)  echo fd8571b8162f4020232d886f17340bcf92e1722985ae3b4c1d096157826c0fbe ;;
        darwin-amd64) echo 998fb3301c1d77452bdfc481f61353e2e4a3b16c97a6b725c2b7beee5464c8c2 ;;
        darwin-arm64) echo f7c71b553316f822bdd860a3ea527ebefb2f8e944e5b7dfd419ae2653cf3ba01 ;;
        *) return 1 ;;
    esac
}

promtool_platform() {
    local os arch
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        *)
            echo "unsupported architecture: $arch" >&2
            return 1
            ;;
    esac
    case "$os" in
        linux|darwin) echo "${os}-${arch}" ;;
        *)
            echo "unsupported OS: $os" >&2
            return 1
            ;;
    esac
}

install_promtool() {
    local platform sha url tmp archive dest
    platform="$(promtool_platform)"
    sha="$(promtool_sha256 "$platform")"
    dest="$LOCALBIN/promtool-${PROMETHEUS_VERSION}"
    if [[ -x "$dest" ]]; then
        printf '%s\n' "$dest"
        return 0
    fi
    mkdir -p "$LOCALBIN"
    url="https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/prometheus-${PROMETHEUS_VERSION}.${platform}.tar.gz"
    tmp="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf -- $(printf '%q' "$tmp")" RETURN
    archive="$tmp/prometheus.tar.gz"
    echo "Downloading promtool from $url" >&2
    curl -fsSL "$url" -o "$archive"
    if command -v sha256sum >/dev/null 2>&1; then
        echo "$sha  $archive" | sha256sum -c - >&2
    else
        echo "$sha  $archive" | shasum -a 256 -c - >&2
    fi
    tar -xzf "$archive" -C "$tmp" --strip-components=1 "prometheus-${PROMETHEUS_VERSION}.${platform}/promtool"
    mv "$tmp/promtool" "$dest"
    chmod +x "$dest"
    printf '%s\n' "$dest"
}

resolve_promtool() {
    if [[ -n "$PROMTOOL" ]]; then
        command -v "$PROMTOOL" >/dev/null 2>&1 || [[ -x "$PROMTOOL" ]] || {
            echo "PROMTOOL=$PROMTOOL not found or not executable" >&2
            exit 1
        }
        printf '%s\n' "$PROMTOOL"
        return 0
    fi
    if command -v promtool >/dev/null 2>&1; then
        command -v promtool
        return 0
    fi
    local dest="$LOCALBIN/promtool-${PROMETHEUS_VERSION}"
    if [[ -x "$dest" ]]; then
        printf '%s\n' "$dest"
        return 0
    fi
    install_promtool
}

extract_rule_groups() {
    python3 -c '
import re
import sys

text = sys.stdin.read()
# Drop a leading Helm document marker so the search is on the object body.
text = re.sub(r"^---\n", "", text, count=1)
match = re.search(r"(?m)^spec:\n  groups:\n", text)
if not match:
    sys.stderr.write("could not find spec.groups in rendered PrometheusRule\n")
    sys.exit(1)
body = text[match.end() - len("  groups:\n"):]
lines = []
for line in body.splitlines():
    if line.startswith("---"):
        break
    if line.startswith("  "):
        lines.append(line[2:])
    elif line == "":
        lines.append("")
    else:
        sys.stderr.write("unexpected unindented line in spec.groups: %r\n" % (line,))
        sys.exit(1)
sys.stdout.write("\n".join(lines).rstrip() + "\n")
'
}

if ! command -v helm >/dev/null 2>&1; then
    echo "helm not found in PATH" >&2
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "curl not found in PATH" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not found in PATH" >&2
    exit 1
fi
if [[ ! -f "$TEST_FILE" ]]; then
    echo "missing $TEST_FILE" >&2
    exit 1
fi

PROMTOOL_BIN="$(resolve_promtool)"

workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT

echo "Rendering PrometheusRule from $CHART_DIR"
rendered="$workdir/rendered.yaml"
helm template rules "$CHART_DIR" \
    --set prometheusRules.enabled=true \
    --show-only templates/prometheusrules.yaml \
    > "$rendered"

if grep -E 'rate\(\{__name__' "$rendered"; then
    echo "rate() over a {__name__=~...} selector drops metric names and can collide" >&2
    exit 1
fi

extract_rule_groups < "$rendered" > "$workdir/prometheus-rules.yaml"
cp "$TEST_FILE" "$workdir/prometheus-rules-test.yaml"

# Every alert the chart ships must have at least one unit test.
untested="$(python3 - "$workdir/prometheus-rules.yaml" "$TEST_FILE" <<'PY'
import re
import sys

rules = open(sys.argv[1]).read()
tests = open(sys.argv[2]).read()
alerts = set(re.findall(r"(?m)^\s*- alert:\s*(\S+)", rules))
tested = set(re.findall(r"(?m)^\s*alertname:\s*(\S+)", tests))
print(" ".join(sorted(alerts - tested)))
PY
)"
if [[ -n "$untested" ]]; then
    echo "PrometheusRule alerts without a promtool unit test in $TEST_FILE: $untested" >&2
    exit 1
fi

echo "promtool check rules ($PROMTOOL_BIN)"
"$PROMTOOL_BIN" check rules "$workdir/prometheus-rules.yaml"

echo "promtool test rules"
"$PROMTOOL_BIN" test rules "$workdir/prometheus-rules-test.yaml"
