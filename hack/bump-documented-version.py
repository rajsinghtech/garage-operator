#!/usr/bin/env python3
"""Rewrite documented install pins to match a release version.

chart-bump already updates Chart.yaml and values.yaml. Docs and the chart
README historically lagged, so users kept seeing 0.7.4 after later tags.
"""

from __future__ import annotations

import argparse
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

def rewrite(text: str, old_tag: str, new_tag: str) -> str:
    old_plain = old_tag.lstrip("v")
    new_plain = new_tag.lstrip("v")
    old_v = f"v{old_plain}"
    new_v = f"v{new_plain}"
    # Replace longer v-prefixed forms first so v0.7.7 does not become vv0.7.8.
    return text.replace(old_v, new_v).replace(old_plain, new_plain)


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
