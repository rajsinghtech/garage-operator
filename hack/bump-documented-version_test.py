#!/usr/bin/env python3

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "bump_documented_version",
    Path(__file__).with_name("bump-documented-version.py"),
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_rewrites_v_prefixed_and_plain_versions():
    src = """IMAGE=ghcr.io/rajsinghtech/garage-operator:v0.7.7
helm install --version 0.7.7
Chart and image version `v0.7.7` in this repository
"""
    got = mod.rewrite(src, "v0.7.7", "v0.7.8")
    assert "v0.7.7" not in got
    assert "0.7.7" not in got
    assert "v0.7.8" in got
    assert "--version 0.7.8" in got


if __name__ == "__main__":
    test_rewrites_v_prefixed_and_plain_versions()
    print("ok")
