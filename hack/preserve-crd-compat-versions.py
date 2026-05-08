#!/usr/bin/env python3
"""Re-apply compatibility-only CRD versions after controller-gen.

controller-gen only emits versions backed by Go API packages. We intentionally
keep a small number of old, non-storage versions in CRDs so Kubernetes accepts
upgrades from clusters whose CRD status.storedVersions still mentions them.
"""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]

COMPAT_VERSIONS = {
    "garage.rajsingh.info_garagebuckets.yaml": ROOT
    / "config/crd/compat/garagebucket_v1alpha1_version.yaml",
}


def version_name_present(crd_text: str, version_name: str) -> bool:
    return f"\n    name: {version_name}\n" in crd_text or crd_text.startswith(
        f"    name: {version_name}\n"
    )


def main() -> int:
    crd_dir = ROOT / "config/crd/bases"
    changed = False

    for crd_name, compat_path in COMPAT_VERSIONS.items():
        crd_path = crd_dir / crd_name
        if not crd_path.exists():
            print(f"missing CRD: {crd_path}", file=sys.stderr)
            return 1

        crd_text = crd_path.read_text()
        compat_text = compat_path.read_text().rstrip() + "\n"
        version_name = None
        for line in compat_text.splitlines():
            if line.startswith("  name: "):
                version_name = line.removeprefix("  name: ").strip()
                break

        if not version_name:
            print(f"cannot find version name in {compat_path}", file=sys.stderr)
            return 1
        if version_name_present(crd_text, version_name):
            continue
        if "  versions:\n" not in crd_text:
            print(f"cannot find spec.versions in {crd_path}", file=sys.stderr)
            return 1

        indented_compat = "".join(f"  {line}\n" for line in compat_text.splitlines())
        crd_path.write_text(
            crd_text.replace("  versions:\n", f"  versions:\n{indented_compat}", 1)
        )
        changed = True
        print(f"preserved {crd_name} version {version_name}")

    if not changed:
        print("CRD compatibility versions already present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
