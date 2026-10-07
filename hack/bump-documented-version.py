#!/usr/bin/env python3
"""Rewrite documented install pins to match a release version.

chart-bump already updates Chart.yaml and values.yaml. Docs and the chart
README historically lagged, so users kept seeing 0.7.4 after later tags.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DOC_FILES = (
    Path("README.md"),
    Path("charts/garage-operator/README.md"),
    Path("docs/getting-started/installation.md"),
    Path("docs/operations/upgrades.md"),
    Path("docs/reference/helm.md"),
    Path("docs/reference/compatibility.md"),
)

# "first release `v0.8.0`" names the first tag of a release line. A patch
# release keeps it; only the first release of a new minor line changes it.
FIRST_RELEASE = re.compile(r"(first release `)v?[0-9]+\.[0-9]+\.[0-9]+(`)")
FIRST_RELEASE_PLACEHOLDER = "\x00FIRST_RELEASE_{}\x00"


def release_line(tag: str) -> tuple[str, str]:
    major, minor = tag.lstrip("v").split(".")[:2]
    return major, minor


def rewrite(text: str, old_tag: str, new_tag: str) -> str:
    old_plain = old_tag.lstrip("v")
    new_plain = new_tag.lstrip("v")
    old_v = f"v{old_plain}"
    new_v = f"v{new_plain}"
    new_line = release_line(new_tag) != release_line(old_tag)

    # Shield "first release" tokens from the generic pin rewrite below.
    kept: list[str] = []

    def shield(match: re.Match) -> str:
        if new_line:
            kept.append(f"{match.group(1)}{new_v}{match.group(2)}")
        else:
            kept.append(match.group(0))
        return FIRST_RELEASE_PLACEHOLDER.format(len(kept) - 1)

    text = FIRST_RELEASE.sub(shield, text)
    # Replace longer v-prefixed forms first so v0.7.7 does not become vv0.7.8.
    text = text.replace(old_v, new_v).replace(old_plain, new_plain)
    if new_line:
        old_major, old_minor = release_line(old_tag)
        new_major, new_minor = release_line(new_tag)
        text = text.replace(f"v{old_major}.{old_minor}.x", f"v{new_major}.{new_minor}.x")
    for i, token in enumerate(kept):
        text = text.replace(FIRST_RELEASE_PLACEHOLDER.format(i), token)
    return text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--from-tag", required=True, help="Current documented tag, e.g. v0.7.7")
    parser.add_argument("--to-tag", required=True, help="New release tag, e.g. v0.7.8")
    args = parser.parse_args()

    root = Path.cwd()
    changed = []
    for rel in DOC_FILES:
        path = root / rel
        original = path.read_text()
        updated = rewrite(original, args.from_tag, args.to_tag)
        if updated != original:
            path.write_text(updated)
            changed.append(str(rel))
    if changed:
        print("Updated documented version pins:")
        for name in changed:
            print(f"  {name}")
    else:
        print("No documented version pins needed updating")
    return 0


if __name__ == "__main__":
    sys.exit(main())
