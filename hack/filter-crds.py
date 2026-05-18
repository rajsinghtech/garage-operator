#!/usr/bin/env python3
"""Filter a kustomize-built YAML stream down to only CustomResourceDefinitions.

The naive 'awk RS=---' splitter trips on long description blocks that happen to
end with '---' (e.g. 'rw-rw----' in the SecurityContext.fsGroup description).
This script splits on a stricter pattern: a line that is exactly '---'.
"""

import sys


def main() -> int:
    data = sys.stdin.read()
    lines = data.split("\n")
    docs = []
    current: list[str] = []
    for line in lines:
        if line == "---":
            if current:
                docs.append("\n".join(current))
                current = []
        else:
            current.append(line)
    if current:
        docs.append("\n".join(current))

    out: list[str] = []
    for doc in docs:
        if not doc.strip():
            continue
        head = "\n".join(doc.splitlines()[:5])
        if "kind: CustomResourceDefinition" in head:
            out.append(doc)

    if out:
        print("---")
        print("\n---\n".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
