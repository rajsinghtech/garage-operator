#!/usr/bin/env python3

# Derived from https://github.com/yannh/kubeconform/blob/master/scripts/openapi2jsonschema.py
# Converts Kubernetes CRD OpenAPI schemas to JSON Schema for editor validation

import yaml
import json
import sys
import os


def additional_properties(data, skip=False):
    """
    Recreates kubectl validation behavior.
    Adds additionalProperties: false to objects with properties defined.
    https://github.com/kubernetes/kubernetes/blob/225b9119d6a8f03fcbe3cc3d590c261965d928d0/pkg/kubectl/validation/schema.go#L312
    """
    if isinstance(data, dict):
        if "properties" in data and not skip:
            if "additionalProperties" not in data:
                data["additionalProperties"] = False
        for _, v in data.items():
            additional_properties(v)
    return data


def replace_int_or_string(data):
    """Convert Kubernetes int-or-string format to JSON Schema oneOf."""
    new = {}
    try:
        for k, v in iter(data.items()):
            new_v = v
            if isinstance(v, dict):
                if "format" in v and v["format"] == "int-or-string":
                    new_v = {"oneOf": [{"type": "string"}, {"type": "integer"}]}
                else:
                    new_v = replace_int_or_string(v)
            elif isinstance(v, list):
                new_v = [replace_int_or_string(x) for x in v]
            else:
                new_v = v
            new[k] = new_v
        return new
    except AttributeError:
        return data


def allow_null_optional_fields(data, parent=None, grand_parent=None, key=None):
    """Allow null for optional fields (fields not in 'required' array)."""
    new = {}
    try:
        for k, v in iter(data.items()):
            new_v = v
            if isinstance(v, dict):
                new_v = allow_null_optional_fields(v, data, parent, k)
            elif isinstance(v, list):
                new_v = [allow_null_optional_fields(x, v, parent, k) for x in v]
            elif isinstance(v, str):
                is_non_null_type = k == "type" and v != "null"
                has_required_fields = grand_parent and "required" in grand_parent
                if is_non_null_type and not has_required_fields:
                    new_v = [v, "null"]
            new[k] = new_v
        return new
    except AttributeError:
        return data


def construct_value(loader, node):
    """Handle YAML nodes that start with '=' (see https://github.com/yaml/pyyaml/issues/89)."""
    if not isinstance(node, yaml.ScalarNode):
        raise yaml.constructor.ConstructorError(
            "while constructing a value",
            node.start_mark,
            "expected a scalar, but found %s" % node.id,
            node.start_mark,
        )
    yield str(node.value)


def write_schema_file(schema, filename, output_dir):
    """Process and write JSON schema to file."""
    schema = additional_properties(
        schema, skip=not os.getenv("DENY_ROOT_ADDITIONAL_PROPERTIES")
    )
    schema = replace_int_or_string(schema)

    # Add $schema for editor compatibility
    schema["$schema"] = "http://json-schema.org/draft-07/schema#"

    schema_json = json.dumps(schema, indent=2)

    filepath = os.path.join(output_dir, os.path.basename(filename))
    with open(filepath, "w") as f:
        f.write(schema_json)
        f.write("\n")
    print(f"  Generated: {os.path.basename(filename)}")


def process_crd_file(crd_file, output_dir, filename_format):
    """Process a CRD file and generate JSON schemas for each version."""
    with open(crd_file) as f:
        defs = []
        yaml.SafeLoader.add_constructor("tag:yaml.org,2002:value", construct_value)
        for y in yaml.load_all(f, Loader=yaml.SafeLoader):
            if y is None:
                continue
            if "items" in y:
                defs.extend(y["items"])
            if "kind" not in y:
                continue
            if y["kind"] != "CustomResourceDefinition":
                continue
            defs.append(y)

        for y in defs:
            if "spec" not in y:
                continue

            kind = y["spec"]["names"]["kind"]
            group = y["spec"]["group"]

            # Handle versioned schemas (v1 CRDs)
            if "versions" in y["spec"] and y["spec"]["versions"]:
                for version in y["spec"]["versions"]:
                    # Skip non-served versions (deprecated stubs kept for migration)
                    if not version.get("served", True):
                        continue
                    schema = None

                    # Try version-specific schema first
                    if "schema" in version and "openAPIV3Schema" in version["schema"]:
                        schema = version["schema"]["openAPIV3Schema"]
                    # Fall back to spec-level validation
                    elif (
                        "validation" in y["spec"]
                        and "openAPIV3Schema" in y["spec"]["validation"]
                    ):
                        schema = y["spec"]["validation"]["openAPIV3Schema"]

                    if schema:
                        filename = (
                            filename_format.format(
                                kind=kind.lower(),
                                group=group.split(".")[0],
                                fullgroup=group,
                                version=version["name"],
                            )
                            + ".json"
                        )
                        write_schema_file(schema, filename, output_dir)

            # Handle legacy single-version CRDs
            elif (
                "validation" in y["spec"]
                and "openAPIV3Schema" in y["spec"]["validation"]
            ):
                filename = (
                    filename_format.format(
                        kind=kind.lower(),
                        group=group.split(".")[0],
                        fullgroup=group,
                        version=y["spec"]["version"],
                    )
                    + ".json"
                )
                write_schema_file(
                    y["spec"]["validation"]["openAPIV3Schema"], filename, output_dir
                )


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} OUTPUT_DIR CRD_FILE [CRD_FILE ...]")
        print("\nGenerates JSON schemas from Kubernetes CRDs for editor validation.")
        print("\nEnvironment variables:")
        print("  FILENAME_FORMAT  Output filename format (default: {kind}_{version})")
        print("                   Available: {kind}, {group}, {fullgroup}, {version}")
        print("  DENY_ROOT_ADDITIONAL_PROPERTIES  Set to add additionalProperties:false at root")
        sys.exit(1)

    output_dir = sys.argv[1]
    os.makedirs(output_dir, exist_ok=True)

    filename_format = os.getenv("FILENAME_FORMAT", "{kind}_{version}")

    print("Generating JSON schemas from CRDs...")
    for crd_file in sys.argv[2:]:
        process_crd_file(crd_file, output_dir, filename_format)
    print(f"JSON schemas written to {output_dir}/")

    sys.exit(0)
