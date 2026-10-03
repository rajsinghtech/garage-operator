#!/usr/bin/env bash
# Print the newest published dxflrs/garage image built from Garage's main-v2
# branch, as a digest-pinned reference (dxflrs/garage:<commit>@sha256:...).
#
# Garage publishes commit-SHA tags to Docker Hub for main-v2 builds but no
# floating "main-v2" tag, and the newest commit may not be built yet. This walks
# the first-parent history of main-v2 from the tip and returns the first commit
# whose image exists.
#
# Usage: hack/resolve-garage-canary-image.sh
# Env:   GARAGE_CANARY_REPO     git URL (default: Deuxfleurs Forgejo)
#        GARAGE_CANARY_BRANCH   branch (default: main-v2)
#        GARAGE_CANARY_DEPTH    commits to inspect (default: 30)
#        GARAGE_CANARY_IMAGE_REPO  Docker Hub repo (default: dxflrs/garage)
set -euo pipefail

REPO="${GARAGE_CANARY_REPO:-https://git.deuxfleurs.fr/Deuxfleurs/garage.git}"
BRANCH="${GARAGE_CANARY_BRANCH:-main-v2}"
DEPTH="${GARAGE_CANARY_DEPTH:-30}"
IMAGE_REPO="${GARAGE_CANARY_IMAGE_REPO:-dxflrs/garage}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git clone --quiet --bare --depth "$DEPTH" --single-branch --branch "$BRANCH" \
  --filter=blob:none "$REPO" "$tmp/repo" >&2

while read -r sha; do
  [ -n "$sha" ] || continue
  url="https://hub.docker.com/v2/repositories/${IMAGE_REPO}/tags/${sha}"
  body="$(curl --silent --show-error --location --retry 3 --retry-delay 2 \
    --write-out '\n%{http_code}' "$url" || true)"
  status="${body##*$'\n'}"
  body="${body%$'\n'*}"
  if [ "$status" = "200" ]; then
    digest="$(printf '%s' "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])')"
    case "$digest" in
      sha256:????????????????????????????????????????????????????????????????) ;;
      *) echo "unexpected digest '$digest' for ${sha}" >&2; exit 1 ;;
    esac
    echo "using ${IMAGE_REPO}:${sha} (${BRANCH} commit $(git -C "$tmp/repo" log -1 --format='%h %s' "$sha"))" >&2
    printf '%s:%s@%s\n' "$IMAGE_REPO" "$sha" "$digest"
    exit 0
  elif [ "$status" != "404" ]; then
    echo "Docker Hub returned HTTP ${status} for ${sha}; not treating as 'unpublished'" >&2
    exit 1
  fi
  echo "no published image for ${sha} yet; trying the previous commit" >&2
done < <(git -C "$tmp/repo" rev-list --first-parent -n "$DEPTH" "$BRANCH")

echo "none of the last ${DEPTH} ${BRANCH} commits has a ${IMAGE_REPO} image" >&2
exit 1
