#!/usr/bin/env bash
# Install a pinned kind release with hardcoded checksums.
# Avoids helm/kind-action's download of kind-linux-*.sha256sum, which intermittently
# returns an empty body from GitHub release assets and fails with:
#   sha256sum: 'standard input': no properly formatted checksum lines found
set -euo pipefail

KIND_VERSION="${KIND_VERSION:-v0.33.0}"
DEST="${KIND_INSTALL_DIR:-${HOME}/.local/bin}"
mkdir -p "${DEST}"

arch="$(uname -m)"
case "${arch}" in
  x86_64|amd64) arch=amd64; sha256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d ;;
  aarch64|arm64) arch=arm64; sha256=20022bee6cfcd5086cb7234d218e3454e6090022f2a8f55d1fa7fcf42c3867a2 ;;
  *)
    echo "unsupported architecture: ${arch}" >&2
    exit 1
    ;;
esac

# Checksums above are for KIND_VERSION=v0.33.0 only.
if [[ "${KIND_VERSION}" != "v0.33.0" ]]; then
  echo "hack/install-kind.sh: update pinned checksums before changing KIND_VERSION (want v0.33.0, got ${KIND_VERSION})" >&2
  exit 1
fi

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT
url="https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-${arch}"
echo "Downloading ${url}"
curl -fsSL -o "${tmp}" "${url}"
echo "${sha256}  ${tmp}" | sha256sum -c -
install -m 0755 "${tmp}" "${DEST}/kind"
echo "Installed $(${DEST}/kind version) to ${DEST}/kind"
# Ensure subsequent steps find it (GHA already puts ~/.local/bin on PATH usually;
# export for the current job step chain via GITHUB_PATH when present).
if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${DEST}" >> "${GITHUB_PATH}"
fi
