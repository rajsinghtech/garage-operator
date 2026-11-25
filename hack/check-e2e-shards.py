#!/usr/bin/env python3
"""Verify the Ginkgo E2E shard matrix covers every spec.

Builds the e2e suite, dry-runs it once unfiltered and once per shard filter in
.github/e2e-shards.json, and fails if any spec runs in no shard, or if a
spec other than an Ordered "drain-setup" prerequisite runs in more than one
shard. core-arm64 is an intentional architecture re-run and is excluded.

Usage: hack/check-e2e-shards.py [path/to/e2e.test]
"""
import collections
import json
import os
import subprocess
import sys
import tempfile


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHARDS_FILE = os.path.join(ROOT, ".github", "e2e-shards.json")
REPEAT_SHARDS = {"core-arm64"}


def build(binary):
    subprocess.run(
        ["go", "test", "-c", "-tags=e2e", "-o", binary, "./test/e2e/"],
        cwd=ROOT, check=True,
    )


def specs(binary, label_filter):
    with tempfile.TemporaryDirectory() as tmp:
        report = os.path.join(tmp, "report.json")
        subprocess.run(
            [binary, "-ginkgo.dry-run", "-ginkgo.label-filter=" + label_filter,
             "-ginkgo.json-report=" + report],
            cwd=os.path.join(ROOT, "test", "e2e"), check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        with open(report) as fh:
            data = json.load(fh)
    found = {}
    for spec in data[0].get("SpecReports") or []:
        if spec.get("LeafNodeType") != "It" or spec.get("State") != "passed":
            continue
        name = " / ".join(spec.get("ContainerHierarchyTexts") or []) + " :: " + spec["LeafNodeText"]
        found[name] = set(spec.get("LeafNodeLabels") or [])
    return found


def main():
    with open(SHARDS_FILE) as fh:
        shards = json.load(fh)["shard"]

    with tempfile.TemporaryDirectory() as tmp:
        binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(tmp, "e2e.test")
        if len(sys.argv) <= 1:
            build(binary)
        everything = specs(binary, "")
        runs = collections.defaultdict(list)
        for shard in shards:
            if shard["name"] in REPEAT_SHARDS:
                continue
            got = specs(binary, shard["filter"])
            print(f"{shard['name']:>24}: {len(got)} specs")
            for name in got:
                runs[name].append(shard["name"])
        for ext_name, ext_filter in [("external-gateway", "external-gateway")]:
            got = specs(binary, ext_filter)
            print(f"{ext_name:>24}: {len(got)} specs (dedicated job)")
            for name in got:
                runs[name].append(ext_name)

    failed = False
    for name in sorted(set(everything) - set(runs)):
        print(f"::error::spec runs in no E2E shard: {name}")
        failed = True
    for name, where in sorted(runs.items()):
        if len(where) > 1 and "drain-setup" not in everything.get(name, set()):
            print(f"::error::spec runs in {len(where)} shards ({', '.join(where)}): {name}")
            failed = True
    print(f"{len(everything)} specs, {len(runs)} covered")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
