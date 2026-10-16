# Use TLS with Garage

Garage does not terminate TLS itself. To encrypt client traffic, put TLS in front of Garage. This page covers what Garage does natively, where to terminate TLS, and how to use Kubernetes pod certificates for a sidecar.

## What Garage does natively

| Traffic | Port | Transport | Authentication |
| --- | --- | --- | --- |
| S3 API | 3900 | Plain HTTP | S3 signatures (access key + secret) |
| Web endpoint | 3902 | Plain HTTP | None (public website buckets) |
| Admin API | 3903 | Plain HTTP | Bearer admin token |
| RPC between nodes | 3901 | Garage's own encrypted handshake | Shared `rpc_secret` plus each node's `node_key` |

Garage encrypts and authenticates RPC between nodes with the shared `rpc_secret`; it has no TLS option for RPC. Every node, including nodes in [federated clusters](federation.md), must share the same RPC Secret. Keep port 3901 on a private network or a tunnel you trust.

!!! warning "`spec.security.tls` is rejected"
    `spec.security.tls` is still in the schema for API compatibility, but admission rejects any value in it. Garage removed its `rpc_tls` setting, so the operator has nothing to configure. Remove the block from your manifests and use one of the options below.

## Terminate TLS at an Ingress or Gateway

This is the simplest option for S3 and web traffic coming from outside the cluster. Point an Ingress or Gateway API route at the operator-managed Service and let your controller (with cert-manager or a cloud certificate) serve TLS:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: garage-s3
spec:
  parentRefs:
    - name: public-gateway        # Gateway with an HTTPS listener
  hostnames: ["s3.example.net"]
  rules:
    - backendRefs:
        - name: garage            # GarageCluster Service
          port: 3900
```

A website bucket's Ingress can use an existing TLS Secret through `GarageBucket` `spec.websiteExposure.ingress.tlsSecretName`. When TLS is terminated in front of the web endpoint, set `GarageCluster` `spec.webApi.scheme: https` so published website URLs are correct.

S3 clients sign the `Host` header. Keep the proxy from rewriting it, and configure clients for the public hostname.

## Use a service mesh

A mesh (Istio, Linkerd, Cilium) can add mTLS to S3, admin, and web traffic inside the cluster without changing Garage. It can also carry RPC between nodes, but Garage nodes dial each other's advertised RPC address directly. Make sure the mesh handles those pod-to-pod connections (and cross-cluster ones for federation) as a transparent tunnel.

## Pod certificates and ClusterTrustBundles

Kubernetes 1.37 made [pod certificates](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#pod-certificate-requests) and ClusterTrustBundles GA, enabled by default. The kubelet generates a private key, sends a `PodCertificateRequest` to a signer, writes the issued certificate into the pod, and refreshes it before it expires.

Kubernetes ships **no built-in signer** for pod certificates. You must install a signer controller that answers requests for your `signerName` and publishes its CA as a signer-linked ClusterTrustBundle. [Tinycert](https://github.com/ahmedtd/tinycert) is a reference example, not a production signer. Certificates from any signer last at most 91 days, and usually much less, so whatever reads them must reload rotated files.

The operator does not manage any of this. Use `extraVolumes` and `extraContainers` (see [sidecars and extra volumes](configuration.md#init-containers-sidecars-and-extra-volumes)) to add a TLS proxy beside Garage. This example puts a [ghostunnel](https://github.com/ghostunnel/ghostunnel) sidecar in front of the S3 API on gateway pods:

```yaml
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: garage
spec:
  gateway:
    replicas: 2
    extraVolumes:
      - name: tls
        projected:
          sources:
            - podCertificate:
                signerName: example.com/service-tls   # your installed signer
                keyType: ECDSAP256
                maxExpirationSeconds: 86400
                credentialBundlePath: credentials.pem # private key + chain in one file
            - clusterTrustBundle:
                signerName: example.com/client-ca     # CA for client certificates (mTLS)
                labelSelector: {}
                path: client-ca.pem
    extraContainers:
      - name: s3-tls
        image: ghostunnel/ghostunnel:v1.8.4
        args:
          - server
          - --listen=0.0.0.0:3443
          - --target=127.0.0.1:3900
          - --keystore=/tls/credentials.pem
          - --cacert=/tls/client-ca.pem
          - --allow-all                 # any client cert signed by client-ca
          - --timed-reload=1h           # pick up rotated certificates
        ports:
          - name: s3-tls
            containerPort: 3443
        volumeMounts:
          - name: tls
            mountPath: /tls
            readOnly: true
```

Notes:

- `credentialBundlePath` writes the key and chain to one file, so the proxy never reads a half-rotated pair. Use `keyPath` and `certificateChainPath` instead only if your proxy needs separate files.
- `userAnnotations` on the `podCertificate` source are passed to the signer as `unverifiedUserAnnotations`. Use them only if your signer documents them.
- Drop the `clusterTrustBundle` source and `--cacert` for server-only TLS. Clients then trust the server's CA by mounting the same signer's ClusterTrustBundle.
- Expose the sidecar port with your own Service; the operator-managed Service still targets Garage's plain ports.
- The RPC port can't use this pattern unless you also tunnel the dialing side, because Garage dials peers directly.

## HTTPS admin endpoints

Fields that take an Admin API URL, `remoteClusters[].connection.adminApiEndpoint` and `connectTo.adminApiEndpoint`, accept `https://`. The operator verifies these endpoints against the operator image's **system CA roots only**. You can't configure a custom CA, a client certificate, or skip verification yet. Use a certificate from a publicly trusted CA, or keep admin traffic on a private network over plain HTTP with the admin token.
