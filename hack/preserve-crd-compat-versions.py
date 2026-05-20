#!/usr/bin/env python3
"""Re-apply compatibility-only CRD versions and conversion strategy after
controller-gen.

controller-gen only emits versions backed by Go API packages. We intentionally
keep a small number of old, non-storage versions in CRDs so Kubernetes accepts
upgrades from clusters whose CRD status.storedVersions still mentions them.

We also inject the conversion webhook stanza on the GarageCluster CRD here,
since controller-gen does not produce it from kubebuilder markers and the
webhook is required to bridge v1beta1 ↔ v1beta2 reads.
"""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]

V1ALPHA1_STUB = ROOT / "config/crd/compat/v1alpha1_stub_version.yaml"

# CRDs that need legacy version entries preserved so Kubernetes accepts an upgrade
# when the cluster still has those versions listed in status.storedVersions.
#
# The garagebucket compat entry retains the full historical schema with
# served=true because older clients may still read v1alpha1 objects.
# The other CRDs use a minimal served=false/storage=false stub — v1alpha1
# was never a storage version for them, so no decoding is required, but
# Kubernetes' invariant "every entry in status.storedVersions must still
# appear in spec.versions" forces us to keep the entry around.
COMPAT_VERSIONS = {
    "garage.rajsingh.info_garagebuckets.yaml": ROOT
    / "config/crd/compat/garagebucket_v1alpha1_version.yaml",
    "garage.rajsingh.info_garageadmintokens.yaml": V1ALPHA1_STUB,
    "garage.rajsingh.info_garageclusters.yaml": V1ALPHA1_STUB,
    "garage.rajsingh.info_garagekeys.yaml": V1ALPHA1_STUB,
    "garage.rajsingh.info_garagenodes.yaml": V1ALPHA1_STUB,
}

# CRDs that need a conversion webhook (multi-version with non-identical schemas).
# The placeholder template is rendered/swapped at install time by the Helm chart
# (cert-manager CA bundle injection) — but we still need the structural stanza
# present in the base CRD so kubectl-based installs work too.
CONVERSION_WEBHOOK_CRDS = {
    "garage.rajsingh.info_garageclusters.yaml": (
        "  conversion:\n"
        "    strategy: Webhook\n"
        "    webhook:\n"
        "      conversionReviewVersions:\n"
        "      - v1\n"
        "      clientConfig:\n"
        "        service:\n"
        "          name: webhook-service\n"
        "          namespace: system\n"
        "          path: /convert\n"
    ),
}


def version_name_present(crd_text: str, version_name: str) -> bool:
    return f"\n    name: {version_name}\n" in crd_text or crd_text.startswith(
        f"    name: {version_name}\n"
    )


def main() -> int:
    crd_dir = ROOT / "config/crd/bases"
    changed = False

    # Spurious CRDs from internal placeholder types that controller-gen
    # picks up from any package containing TypeMeta+ObjectMeta. The
    # LegacyGarageCluster type in api/v1alpha1 exists only to register the
    # v1alpha1 GVK in the runtime scheme (see issue #181); it must never be
    # exposed as its own CRD.
    spurious_crds = [
        "garage.rajsingh.info_legacygarageclusters.yaml",
    ]
    for name in spurious_crds:
        for d in (crd_dir, ROOT / "charts/garage-operator/crd-bases"):
            p = d / name
            if p.exists():
                p.unlink()
                changed = True
                print(f"removed spurious CRD {p}")

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

        indented_compat = "".join(
            f"  {line}\n" if line else "\n" for line in compat_text.splitlines()
        )
        crd_path.write_text(
            crd_text.replace("  versions:\n", f"  versions:\n{indented_compat}", 1)
        )
        changed = True
        print(f"preserved {crd_name} version {version_name}")

    for crd_name, conversion_block in CONVERSION_WEBHOOK_CRDS.items():
        crd_path = crd_dir / crd_name
        if not crd_path.exists():
            print(f"missing CRD: {crd_path}", file=sys.stderr)
            return 1
        crd_text = crd_path.read_text()
        if "\n  conversion:\n" in crd_text:
            continue
        # Insert before `  group:` so the conversion block lives at the top of spec.
        marker = "  group: garage.rajsingh.info\n"
        if marker not in crd_text:
            print(f"cannot find spec.group in {crd_path}", file=sys.stderr)
            return 1
        crd_path.write_text(crd_text.replace(marker, marker + conversion_block, 1))
        changed = True
        print(f"injected conversion webhook stanza into {crd_name}")

    if not changed:
        print("CRD compatibility versions already present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
