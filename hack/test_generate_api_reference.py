"""Contract tests for rendering and checking the public CRD reference."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import yaml

from generate_api_reference import generate, main


def fixture(description="A useful description | with a pipe"):
    return {
        "kind": "CustomResourceDefinition",
        "spec": {
            "group": "example.test",
            "scope": "Namespaced",
            "names": {"kind": "Example"},
            "versions": [
                {"name": "v1alpha1", "served": False},
                {
                    "name": "v1beta1",
                    "served": True,
                    "schema": {
                        "openAPIV3Schema": {
                            "properties": {
                                "spec": {
                                    "type": "object",
                                    "required": ["things"],
                                    "properties": {
                                        "things": {
                                            "type": "array",
                                            "description": description,
                                            "items": {
                                                "type": "object",
                                                "required": ["name"],
                                                "properties": {
                                                    "name": {
                                                        "type": "string",
                                                        "default": "main",
                                                        "enum": ["main", "backup"],
                                                        "pattern": "^([a-z0-9]([-a-z0-9]*[a-z0-9])?)$",
                                                    },
                                                    "settings": {
                                                        "type": "object",
                                                        "additionalProperties": {
                                                            "type": "object",
                                                            "properties": {
                                                                "enabled": {"type": "boolean"}
                                                            },
                                                        },
                                                    },
                                                },
                                            },
                                        }
                                    },
                                }
                            }
                        }
                    },
                },
            ],
        },
    }


class APIReferenceTest(unittest.TestCase):
    def test_served_nested_fields_and_constraints(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            (source / "example.yaml").write_text(yaml.safe_dump(fixture()))
            pages = generate(source)
        self.assertEqual(set(pages), {"index.md", "example-v1beta1.md"})
        page = pages["example-v1beta1.md"]
        self.assertIn("`things` | array of object | required", page)
        self.assertIn("A useful description \\| with a pipe", page)
        self.assertIn("`things[].name` | string | required; default: \"main\"; enum:", page)
        self.assertIn(r"\[a-z0-9\]", page)
        self.assertNotIn("[-a-z0-9]", page)
        self.assertIn("`things[].settings.*.enabled` | boolean", page)

    def test_check_detects_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "crds"
            output = Path(temp) / "docs"
            source.mkdir()
            crd = source / "example.yaml"
            crd.write_text(yaml.safe_dump(fixture()))
            args = ["--crd-dir", str(source), "--output-dir", str(output)]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 0)
                self.assertEqual(main(args + ["--check"]), 0)
            crd.write_text(yaml.safe_dump(fixture("Changed Go comment")))
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args + ["--check"]), 1)

    def test_check_detects_obsolete_page(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "crds"
            output = Path(temp) / "docs"
            source.mkdir()
            (source / "example.yaml").write_text(yaml.safe_dump(fixture()))
            args = ["--crd-dir", str(source), "--output-dir", str(output)]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 0)
            (output / "obsolete.md").write_text("obsolete\n")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args + ["--check"]), 1)


if __name__ == "__main__":
    unittest.main()
