# AWS shared credentials file in generated GarageKey Secrets

## Problem

`GarageKey` generates the access key ID and secret access key as separate
Secret data entries. Some S3 consumers instead accept the standard AWS shared
credentials file through one file path or one `SecretKeySelector`. Users must
currently compose that file outside the operator, which disconnects it from
the generated credential lifecycle.

The existing `secretTemplate` API already uses `include<X>` and `<x>Key` pairs
for optional generated data. The missing capability is another representation
of the same Garage-generated credentials, not a consumer-specific integration.

## Proposed API and reconciliation behavior

Add two optional fields to `GarageKey.spec.secretTemplate`:

```yaml
includeCredentialsFile: true
credentialsFileKey: credentials
credentialsFileProfile: default
```

`includeCredentialsFile` defaults to `false`, `credentialsFileKey` defaults to
`credentials`, and `credentialsFileProfile` defaults to `default`. When
enabled, the controller writes this additional Secret entry:

```ini
[default]
aws_access_key_id=<generated access key ID>
aws_secret_access_key=<generated secret access key>
```

The profile name can be selected with `credentialsFileProfile`; admission
restricts it to a single safe INI section name. The file deliberately excludes
region and endpoint because the AWS shared credentials file is for credential
material; the existing `regionKey` and `endpointKey` fields remain the source
of those values.

The composed value is generated in the same Secret reconciliation as the two
credential fields. If the controller receives replacement credential material,
all three entries are updated together. If Garage does not return the secret
access key on a later reconciliation, the controller first preserves the value
from the owned Secret and then rebuilds the file from that effective value.

Admission validates `credentialsFileKey` as a Kubernetes Secret data key and
rejects collisions with generated fields or `additionalData` when the feature
is enabled.

## Alternatives considered

- A free-form Secret template would support more output formats but introduces
  a much larger API, escaping rules, and credential-leak risks.
- Fixing the profile name to `default` would cover the most common case, but a
  configurable name also supports consumers that select among multiple
  projected Garage credentials without changing the file format.
- Putting region or endpoint in the file would mix the AWS credentials and
  config file formats and duplicate fields already supported by this API.

## Compatibility, migration, and rollback

The feature is opt-in. Existing `GarageKey` resources and generated Secrets do
not gain a new data entry after upgrade. Enabling it adds one entry without
changing existing key names or values, and disabling it removes that generated
entry during reconciliation.

No Garage-side state or credential material is migrated. Rolling back to a
controller version without these fields causes the older controller to omit
the composed entry on its next Secret reconciliation; consumers must switch
back to separate credentials before rollback.

## Failure modes and observability

The credentials file is omitted until both credential values are available,
matching the existing behavior for an unavailable secret access key. Invalid
or colliding data-key names are rejected at admission. Normal GarageKey status
and Secret reconciliation errors remain the observability surface; no new
remote calls or failure branch is introduced.

## Test plan

- Verify the entry is absent when the option is not enabled.
- Verify the default and custom data-key names produce the exact file format.
- Verify default and custom profile names produce the expected INI section.
- Verify admission rejects generated-key collisions.
- Verify replacement secret material updates both the ordinary field and the
  composed file in one reconciliation.
- Regenerate CRDs, Helm CRD copies, JSON schemas, and deepcopy code.
