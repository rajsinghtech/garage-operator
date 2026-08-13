# Installation

This page installs the operator and its CRDs. It does not create a Garage cluster; use the [quickstart](quickstart.md) after the operator is ready.

## Requirements

- Kubernetes `1.25+` for ordinary workloads; `1.27+` for [node-local pools](../node-local-pools.md).
- Helm `3.8+`.
- Garage `v2.0.0+`; the default image is the tested Garage `v2.3.0` digest.
- cert-manager for the admission and conversion webhooks. The chart enables webhooks by default.

The operator must be allowed to watch the namespaces in which its `GarageCluster`, `GarageNode`, bucket, key, and token resources live. A cluster-scoped installation is required for `zoneFrom` and node-local pools.

## Install the latest published chart

```bash
helm install garage-operator \
  oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --namespace garage-operator-system \
  --create-namespace
```

Pin a version in production:

```bash
helm install garage-operator \
  oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --version 0.7.4 \
  --namespace garage-operator-system \
  --create-namespace
```

The chart installs CRDs and keeps them on uninstall by default. It enables:

- conversion and validating webhooks;
- leader election;
- an authenticated HTTPS metrics endpoint and metrics Service;
- restrictive operator pod security defaults.

!!! danger "Do not disable webhooks for production storage"
    `webhooks.enabled=false` removes conversion and admission safety boundaries. It is limited to local development or simple v1beta2-only `EmptyDir` experiments. It is not supported for node-local pools, controller-managed persistent claims, PVC-backed rollout/recovery, or prepared storage deletion.

## Verify the installation

```bash
kubectl -n garage-operator-system rollout status \
  deployment/garage-operator-controller-manager --timeout=180s
kubectl get crd \
  garageclusters.garage.rajsingh.info \
  garagebuckets.garage.rajsingh.info \
  garagekeys.garage.rajsingh.info \
  garagenodes.garage.rajsingh.info
```

Check the chart's rendered configuration before upgrading an existing release:

```bash
helm get values garage-operator \
  --namespace garage-operator-system --all
helm status garage-operator --namespace garage-operator-system
```

## Namespace-scoped operation

Set `watchNamespaces` when the operator should reconcile only selected namespaces. The release namespace is always included. CRDs remain cluster-scoped and must still be installed by a cluster administrator.

```bash
helm upgrade --install garage-operator \
  oci://ghcr.io/rajsinghtech/charts/garage-operator \
  --namespace garage-operator-system \
  --create-namespace \
  --set 'watchNamespaces={storage,team-a,team-b}'
```

Use the chart's `cosi.namespace` when enabling COSI in a separate namespace; authorize that namespace with a `GarageReferenceGrant` in each target cluster namespace.

## Private registries and immutable images

Use `imagePullSecrets` for the operator image and `defaultGarageImage` for Garage pods that omit `spec.image`. For supply-chain policy, use `image.digest` for the operator and pin `spec.image` or `defaultGarageImage` to a digest.

## Verify release artifacts

Released container images and Helm charts are signed with keyless cosign
signing by GitHub Actions and carry provenance attestations. Release images
also carry an SPDX SBOM. Verify the immutable image digest before placing it in
`image.digest` or a `GarageCluster.spec.image`:

```bash
IMAGE=ghcr.io/rajsinghtech/garage-operator:v0.7.4

cosign verify "$IMAGE" \
  --certificate-identity-regexp '^https://github.com/rajsinghtech/garage-operator/\.github/workflows/docker\.yml@refs/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify "oci://$IMAGE" --repo rajsinghtech/garage-operator
cosign download attestation "$IMAGE" \
  --predicate-type https://spdx.dev/Document/v2.3
```

For the Helm chart, first resolve its OCI digest, then verify that digest with
the Helm publishing workflow identity:

```bash
CHART=oci://ghcr.io/rajsinghtech/charts/garage-operator
helm show chart "$CHART" --version 0.7.4

# Resolve the OCI manifest descriptor with an OCI client such as ORAS.
oras manifest fetch --descriptor "$CHART:0.7.4"
# Set CHART_DIGEST to the sha256 digest in that descriptor.
CHART_DIGEST=ghcr.io/rajsinghtech/charts/garage-operator@sha256:<digest>
cosign verify "$CHART_DIGEST" \
  --certificate-identity-regexp '^https://github.com/rajsinghtech/garage-operator/\.github/workflows/helm\.yml@refs/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify "oci://$CHART_DIGEST" --repo rajsinghtech/garage-operator
```

The `install.yaml` asset attached to a GitHub release has a provenance
attestation as well. Download it and verify it against the repository:

```bash
gh release download v0.7.4 --repo rajsinghtech/garage-operator \
  --pattern install.yaml
gh attestation verify install.yaml --repo rajsinghtech/garage-operator
```

Substitute the release being installed for `v0.7.4`. Pin verified image and
chart digests in production; tags alone are mutable references.

## Uninstall

```bash
helm uninstall garage-operator --namespace garage-operator-system
```

CRDs and their custom resources are retained by default. Deleting a CRD deletes its custom resources, so inspect and back up them before removing CRDs:

```bash
kubectl get garageclusters,garagenodes,garagebuckets,garagekeys,garageadmintokens,garagereferencegrants -A -o yaml > garage-operator-resources.yaml
```

The operator does not automatically delete Garage data when its Helm release is removed. Follow the resource-specific [deletion and drain procedure](../operations/maintenance-and-recovery.md) before removing storage.
