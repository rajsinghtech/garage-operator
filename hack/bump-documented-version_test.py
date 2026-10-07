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


COMPAT_ROW = "| Operator `v0.8.x` | Current release line (first release `v0.8.0`) | Chart and image version `v0.8.2` in this repository |\n"


def test_patch_release_keeps_first_release_of_the_line():
    got = mod.rewrite(COMPAT_ROW, "v0.8.2", "v0.8.3")
    assert "first release `v0.8.0`" in got
    assert "Chart and image version `v0.8.3`" in got
    assert "Operator `v0.8.x`" in got


def test_patch_release_from_the_first_release_keeps_it():
    row = COMPAT_ROW.replace("`v0.8.2` in this", "`v0.8.0` in this")
    got = mod.rewrite(row, "v0.8.0", "v0.8.1")
    assert "first release `v0.8.0`" in got
    assert "Chart and image version `v0.8.1`" in got


def test_new_minor_release_starts_a_new_line():
    got = mod.rewrite(COMPAT_ROW, "v0.8.2", "v0.9.0")
    assert "first release `v0.9.0`" in got
    assert "Operator `v0.9.x`" in got
    assert "Chart and image version `v0.9.0`" in got
    assert "0.8" not in got


if __name__ == "__main__":
    test_rewrites_v_prefixed_and_plain_versions()
    test_patch_release_keeps_first_release_of_the_line()
    test_patch_release_from_the_first_release_keeps_it()
    test_new_minor_release_starts_a_new_line()
    print("ok")
