#!/usr/bin/env bash
# Extract the garage binary from a dxflrs/garage image without a container
# runtime, by reading the image straight from the Docker Hub registry API.
#
# Usage: hack/fetch-garage-binary.sh <image> <output-path>
#   <image> is repo:tag, repo@sha256:..., or repo:tag@sha256:... (the digest
#   wins). Only Docker Hub repositories are supported.
# Env:   GARAGE_FETCH_ARCH  image architecture (default: amd64)
set -euo pipefail

image="${1:?usage: $0 <image> <output-path>}"
out="${2:?usage: $0 <image> <output-path>}"
arch="${GARAGE_FETCH_ARCH:-amd64}"

repo="${image%%[:@]*}"
case "$repo" in
  */*) ;;
  *) repo="library/${repo}" ;;
esac
if [[ "$image" == *@sha256:* ]]; then
  ref="${image##*@}"
elif [[ "${image#"${repo}"}" == :* ]]; then
  ref="${image##*:}"
else
  ref="latest"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

token="$(curl -fsSL --retry 3 "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
registry="https://registry-1.docker.io/v2/${repo}"
accept="application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"

fetch() { curl -fsSL --retry 3 -H "Authorization: Bearer ${token}" -H "Accept: ${accept}" "$@"; }

fetch "${registry}/manifests/${ref}" > "$tmp/top.json"
manifest_digest="$(python3 - "$tmp/top.json" "$arch" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
if "manifests" in doc:
    for m in doc["manifests"]:
        p = m.get("platform", {})
        if p.get("os") == "linux" and p.get("architecture") == sys.argv[2]:
            print(m["digest"]); break
    else:
        sys.exit("no linux/%s manifest in index" % sys.argv[2])
else:
    print("")
PY
)"
if [ -n "$manifest_digest" ]; then
  fetch "${registry}/manifests/${manifest_digest}" > "$tmp/manifest.json"
else
  cp "$tmp/top.json" "$tmp/manifest.json"
fi

python3 -c 'import json,sys; [print(l["digest"]) for l in json.load(open(sys.argv[1]))["layers"]]' "$tmp/manifest.json" > "$tmp/layers"
found=""
while read -r layer; do
  fetch "${registry}/blobs/${layer}" -o "$tmp/layer.tgz"
  for name in garage usr/local/bin/garage; do
    if tar -xzf "$tmp/layer.tgz" -C "$tmp" "$name" 2>/dev/null; then
      found="$tmp/$name"
    fi
  done
done < "$tmp/layers"
if [ -z "$found" ]; then
  echo "no garage binary found in ${image}" >&2
  exit 1
fi
mkdir -p "$(dirname "$out")"
install -m 0755 "$found" "$out"
"$out" --version >&2 || true
