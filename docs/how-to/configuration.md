# Configure Garage

`GarageCluster.spec` is the source of truth for the Garage configuration
rendered into managed Pods. The operator writes the supported TOML settings,
creates the matching Service ports, and coordinates identity-bearing rollouts.
Use the corresponding `GarageNode.spec` fields for a per-identity override.

## API listeners

The API Service exposes the listeners that are enabled in the cluster spec.
The defaults are S3 `3900`, web `3902`, Admin `3903`, and K2V `3904`.

```yaml
spec:
  s3Api:
    bindPort: 3900
    region: garage
    rootDomain: ".s3.example.com" # optional virtual-hosted S3 access
  k2vApi:
    bindPort: 3904                 # presence enables K2V
  webApi:
    enabled: true                  # enabled by default
    bindPort: 3902
    rootDomain: ".web.example.com"
  admin:
    bindPort: 3903
    adminTokenSecretRef:
      name: garage-admin-token
      key: admin-token
```

`bindAddress` may be used instead of a port when a wildcard address is needed;
managed listeners must remain reachable from the Service and probes. Admin is
the control plane, not an untrusted public endpoint. Restrict it with network
policy or an authenticated proxy and never expose the RPC port to arbitrary
networks.

### K2V

[K2V](https://garagehq.deuxfleurs.fr/documentation/reference-manual/k2v/)
is Garage's key-value API for many small values. It is separate from S3 and is
disabled when `spec.k2vApi` is omitted. When enabled, the operator adds a `k2v`
port to the cluster API Service and reports its URL in
`status.endpoints.k2v`.

The Garage image must be built with the K2V feature; the operator only renders
the listener and does not add that feature to an image. K2V is an early-stage
Garage API, so use the Garage reference manual and a compatible client for the
request format. Do not assume that an S3 bucket/key Secret is a K2V credential
or that K2V data has the same application semantics as S3 objects.

## Worker tuning

Worker settings are applied through Garage's Admin API to every node on each
reconcile. Omitted fields leave Garage's own defaults unchanged.

```yaml
spec:
  workers:
    scrubTranquility: 10
    resyncWorkerCount: 4
    resyncTranquility: 5
```

| Field | Garage variable | Effect | Range |
| --- | --- | --- | --- |
| `scrubTranquility` | `scrub-tranquility` | Adds pauses between block-integrity checks; higher values reduce I/O and extend the scrub | `>= 0` |
| `resyncWorkerCount` | `resync-worker-count` | Number of parallel block-resync workers; higher values increase throughput and I/O | `1–8` |
| `resyncTranquility` | `resync-tranquility` | Adds pauses between resync operations; higher values reduce I/O and extend recovery | `>= 0` |

Tune these together with disk and CPU capacity. A larger worker count can make
repair finish sooner while competing with foreground S3 traffic. Worker
changes do not replace the [prepared drain](../operations/maintenance-and-recovery.md)
or [repair](../operations/day-2.md#trigger-a-repair-or-scrub) workflows.

## Storage volumes and PVC selectors

The default Auto storage group uses `storage.metadata` for the Garage identity
and metadata database and `storage.data` for object blocks. Each replica owns
its own single-replica StatefulSet and claims. `EmptyDir` is suitable for
experiments only; losing metadata loses the Garage `node_key` identity.

```yaml
spec:
  storage:
    replicas: 3
    metadata:
      size: 10Gi
      storageClassName: fast-ssd
      selector:
        matchLabels:
          garage-volume: metadata
    data:
      size: 2Ti
      storageClassName: bulk-hdd
      selector:
        matchLabels:
          garage-volume: data
```

`selector` is a Kubernetes PV selector for newly created claims. It disables
dynamic provisioning for that claim, so provide a distinct compatible PV for
each metadata, data, and multi-disk path claim. `storageClassName`, access
modes, labels, and annotations are part of the claim template and must match
the PV. A selector does not reselect an already-bound claim.

### Volume attributes (IOPS and throughput)

Set `volumeAttributesClassName` to a Kubernetes `VolumeAttributesClass` to tune
the backend volume of a claim without recreating it:

```yaml
apiVersion: storage.k8s.io/v1
kind: VolumeAttributesClass
metadata:
  name: gold
driverName: ebs.csi.aws.com
parameters:
  iops: "6000"
  throughput: "250"
---
apiVersion: storage.k8s.io/v1
kind: VolumeAttributesClass
metadata:
  name: bulk
driverName: ebs.csi.aws.com
parameters:
  iops: "3000"
  throughput: "125"
---
apiVersion: garage.rajsingh.info/v1beta2
kind: GarageCluster
metadata:
  name: garage
spec:
  storage:
    replicas: 3
    metadata:
      size: 10Gi
      storageClassName: fast-ssd
      volumeAttributesClassName: gold
    data:
      size: 2Ti
      storageClassName: bulk-hdd
      volumeAttributesClassName: bulk
```

New claims are created with the class. For an existing identity the operator
patches the **bound** claim in place, so you can change the value later with
an ordinary edit. Watch progress with `kubectl get garagenode -o yaml`
(`VolumeAttributesClassApplied`) or the cluster's `StorageVolumeAttributesReady`
condition; neither blocks `Ready`, scaling, or rollouts.

!!! warning "Class changes modify live volumes"
    - **Adopting existing claims:** setting the field on a cluster whose claims
      already exist modifies those claims on the next reconcile.
    - **A modification can briefly degrade I/O** on the node while the driver
      applies it. Auto mode changes all nodes together; in Manual layout, edit
      one `GarageNode` at a time.
    - **A configured class cannot be removed** by editing the spec; set another
      class instead. Leaving the field unset makes the operator ignore the
      claim's class.
    - Each volume takes its own value; `storage.data.paths[]` entries do not
      inherit `storage.data.volumeAttributesClassName`.
    - It requires Kubernetes 1.34+ and a CSI driver that supports `ModifyVolume`
      (see [compatibility](../reference/compatibility.md)). The operator reports
      `Unsupported` or `Infeasible` rather than failing the cluster. To cancel a
      rejected change, set the previous class in the spec.
    - It cannot be combined with `EmptyDir` volumes or with a `GarageNode`
      `existingClaim`.
    - **Operator rollback:** an older operator ignores the field. Claims that
      were already modified keep their class.

### Metadata snapshots and write durability

These storage settings are rendered into `garage.toml` for every default
storage identity. Keep `metadataSnapshotsDir` on the persistent metadata volume
if snapshots must survive a Pod replacement; the path is inside the Garage
container. `metadataAutoSnapshotInterval` uses Garage's duration syntax and
must be at least `10m` (the webhook rejects shorter values).

```yaml
spec:
  storage:
    metadataSnapshotsDir: /data/metadata/snapshots
    metadataAutoSnapshotInterval: 6h
    metadataFsync: true
    dataFsync: false
```

| Field | Rendered Garage setting | Effect |
| --- | --- | --- |
| `storage.metadataSnapshotsDir` | `metadata_snapshots_dir` | Directory for metadata snapshot files; use persistent storage for recovery value. |
| `storage.metadataAutoSnapshotInterval` | `metadata_auto_snapshot_interval` | Enables automatic snapshots; accepted values include `10m`, `6h`, and `1h 30m`, with a minimum of `10m`. |
| `storage.metadataFsync` | `metadata_fsync` | Enables fsync for metadata transactions when `true`; may reduce write performance. |
| `storage.dataFsync` | `data_fsync` | Enables fsync for data block writes when `true`; may reduce write performance. |

For a manually managed identity, the corresponding
`GarageNode.spec.storage.metadataSnapshotsDir`,
`metadataAutoSnapshotInterval`, `metadataFsync`, and `dataFsync` fields apply
only to that node. Omitted per-node values inherit the cluster setting; the
boolean fields use pointers so an explicit `false` can override a cluster-level
`true`. Snapshot and fsync settings affect durability and I/O trade-offs, not
the Kubernetes volume lifecycle.

### Multi-HDD data

Use `storage.data.paths` instead of `storage.data.size` when one Garage node
stripes data across multiple disks:

```yaml
spec:
  storage:
    data:
      paths:
        - path: /data/data0
          volume:
            size: 1Ti
            storageClassName: fast-ssd
        - path: /data/data1
          volume:
            size: 4Ti
            storageClassName: bulk-hdd
        - path: /mnt/archive
          readOnly: true
```

Garage uses each writable path's `capacity` as a striping weight; the
filesystem remains the actual limit. A read-only path is a migration aid and
does not require capacity. Auto mode projects the same path layout onto every
default storage identity. Use Manual `GarageNode.spec.storage.dataPaths` for
asymmetric disks.

### Safe changes and growth

For a live identity, volume source, selector, storage class, access mode, mount
path, and single-versus-multi-path topology are immutable safety boundaries.
The operator supports in-place size growth and `volumeAttributesClassName`
changes on the same volume. To change the
topology or claim source:

1. scale the affected Auto group or edge gateway to zero without changing the
   template;
2. wait for the exact Garage roles, Pods, and drain evidence to settle;
3. change the template while it remains at zero;
4. scale up in a separate unchanged request.

Retained claims keep their original selector and class and may be reused to
preserve identity. Never delete a live metadata or data claim to force a
change. For a pre-provisioned claim on a manual node, use
`GarageNode.spec.storage.*.existingClaim`; do not use the deprecated managed
`volumeClaimTemplateSpec` field. To populate new Auto PVCs from a group-aware
snapshot populator on cluster create, set `dataSourceRef` on the volume role
(`storage.metadata`, `storage.data`, `storage.data.paths[].volume`, or
`gateway.metadata`; see [GitOps volume restore](../operations/maintenance-and-recovery.md#gitops-volume-restore-auto-group)).

## Images and Pod templates

At cluster level, `image` wins over `imageRepository`; `imagePullPolicy`,
`imagePullSecrets`, and `serviceAccountName` apply to both tiers. Use
`defaultNodeTags` for tags on Auto-managed nodes. Storage and gateway tiers
have independent resources, scheduling, pod metadata, security contexts,
topology spread, and environment settings. A `GarageNode` can override these
fields for one identity.

```yaml
spec:
  image: registry.example.com/garage:v2.3.0
  imagePullPolicy: IfNotPresent
  imagePullSecrets:
    - name: garage-registry
  serviceAccountName: garage
  defaultNodeTags: [ssd, primary]
  storage:
    resources:
      requests:
        cpu: 500m
        memory: 512Mi
    nodeSelector:
      storage.example.com/class: durable
```

Treat the metadata volume, image, and pod-template rollout as one identity
change. The operator replaces at most one managed identity-bearing workload at
a time and records the handoff in `status.storageRollout`.

## Init containers, sidecars, and extra volumes

`initContainers`, `extraContainers`, and `extraVolumes` add your own containers
and volumes to the Garage pod. They exist on `storage`, `gateway`, each
`storage.nodeLocalPools[].podTemplate`, and `GarageNode.spec`. Typical uses are a
dynamic-DNS updater, a helper that configures a secondary network interface, or
an init step that waits for a virtual IP.

```yaml
spec:
  storage:
    initContainers:
      - name: wait-for-vip
        image: busybox:1.37
        command: ["sh", "-c", "until ip addr show dev eth1 | grep -q 10.20.0.5; do sleep 2; done"]
        securityContext:
          capabilities:
            add: ["NET_ADMIN"]
    extraContainers:
      - name: ddns
        image: ghcr.io/example/ddns:1.4
        envFrom:
          - secretRef:
              name: ddns-credentials
        volumeMounts:
          - name: ddns-state
            mountPath: /var/lib/ddns
    extraVolumes:
      - name: ddns-state
        emptyDir: {}
```

The entries are standard Kubernetes `Container` and `Volume` objects. Rules:

- **Order.** Operator init containers run first, then yours in list order. The
  `garage` container is always `containers[0]`; your containers follow it. Your
  volumes follow the operator's.
- **Native sidecars.** An init container with `restartPolicy: Always` is a native
  sidecar (Kubernetes 1.29+ beta, 1.33+ GA). Any other `restartPolicy` on an init
  container, and any `restartPolicy` on an extra container, is rejected.
- **Reserved names.** Container names `garage`, `purge-cluster-layout`, and
  anything starting with `garage-operator-`, and volume names `config`, `metadata`,
  `data`, `data-<n>`, `rpc-secret`, `admin-token`, and `metrics-token`, belong to the operator. Names must be
  unique across `initContainers` and `extraContainers`.
- **Operator volumes are not mountable.** A container cannot mount `metadata` or
  `data`: that would expose `node_key` and add a second writer to Garage's
  storage. Every mounted volume must be declared in `extraVolumes`. See
  [why metadata is not mountable](../concepts/storage-and-layout.md#extra-containers-and-the-metadata-volume).
- **No second claim writer.** An `extraVolumes` `persistentVolumeClaim` that names
  a claim managed by the operator (labelled `app.kubernetes.io/managed-by: operator`,
  annotated with a GarageNode UID, or named like a StatefulSet claim of this
  cluster) is rejected.
- **Ports and `hostPort`.** A container port that collides with a Garage listener
  (RPC, S3, K2V, web, admin) is rejected, and `hostPort` is rejected. Containers
  share the pod network namespace.
- **Strict decoding.** The CRD schema keeps unknown fields so that the API server
  never prunes a container, but the admission webhook and the controller both
  decode each entry strictly. A typo such as `volumeMount:` is an error, not a
  silent no-op. Each template's three lists are limited to 64 KiB of JSON in
  total.
- **Limits.** At most 16 init containers, 16 extra containers, and 32 extra
  volumes per template.

### Readiness, QoS, and secrets

- Extras are part of pod readiness: the pod is Ready only when every container
  is. A sidecar that fails its readiness probe takes a gateway pod out of the S3
  Service, and a crash-looping sidecar or init container on a storage pod stops
  that identity's rollout. The rollout sequencer never advances to a second
  identity, and you recover by reverting the spec.
- Adding a container without `resources.requests` can move the pod out of the
  `Guaranteed` QoS class if Garage's resources are equal requests and limits.
  Set requests and limits on your containers if QoS matters.
- Secrets referenced by extras follow normal pod semantics: rotating one does not
  restart pods. The operator keeps a Secret that only an extra references when it
  cleans up its own credential snapshots.
- Pod Security Admission, Kyverno, and similar policies in the namespace govern
  what your containers may do (`hostPath`, privileged, capabilities). The
  operator does not add its own policy layer.

### Invalid extras at reconcile time

The webhook rejects invalid extras when it is enabled. The controller re-checks
every reconcile because webhooks can be disabled and an object can predate a
stricter rule. When the extras are invalid the operator does not touch any
workload, so running pods keep their previous spec. It sets the
`PodExtrasValid` condition to `False` on the `GarageCluster`, with a reason of
`DecodeError`, `InvalidContainer`, `ReservedName`, `UnknownVolume`,
`OperatorVolumeMount`, or `ManagedClaimReuse`, and a message naming the field.
For an invalid node-level override the `GarageNode` phase is `Failed` with the
same message. Retries are no faster than every five minutes, and `Phase` does
not change by itself. Fix the spec and the condition returns to `True`.

### GarageNode overrides

On a `GarageNode`, each of the three lists that is set replaces the tier's list
for that node. The lists are independent: setting `extraContainers` on a node
does not change the inherited `initContainers` or `extraVolumes`. Set a list to
`[]` explicitly to opt that node out of an inherited list. Because the merged set
must stay valid, a node that replaces `extraVolumes` must also replace any
inherited container that mounts a volume it removed. Extras are rejected on
external `GarageNode`s (no pod) and on node-local-pool-backed `GarageNode`s (their
pod comes from the pool's DaemonSet; use the pool's `podTemplate`).

### Changing and removing extras

The extras are part of the pod-spec hash, so changing, adding, or removing one
is an ordinary pod-template update and uses the same one-identity-at-a-time
rollout as an image change. The hash is computed over the decoded containers, so
reordering JSON keys or changing whitespace does not cause a rollout.

!!! warning "v1beta1 clients and downgrades"
    `GarageCluster.v1beta1` carries the same three fields and converts them
    without loss, including a v1beta1 write that does not touch them. A client that
    sends a v1beta1 object *without* the fields clears them. If you downgrade the
    operator to a version that predates these fields, its older schema prunes them
    from newly written objects, and running pods keep their extras until the next
    pod-template change.

## Custom environment variables

`storage.env`, `storage.envFrom`, `gateway.env`, `gateway.envFrom`, and the
equivalent `GarageNode` fields support non-identity Garage options and
application-level diagnostics. A node-level `envFrom` replaces the inherited
sources; ordinary node-level `env` entries override inherited ordinary names.

```yaml
spec:
  storage:
    env:
      - name: GARAGE_ALLOW_WORLD_READABLE_SECRETS
        value: "true"
    envFrom:
      - secretRef:
          name: garage-extra-settings
```

The following names are reserved and rejected, including `envFrom` prefixes
that could inject them:

| Reserved variable | Why |
| --- | --- |
| `GARAGE_CONFIG_FILE` | The operator must control the rendered TOML |
| `GARAGE_RPC_SECRET`, `GARAGE_RPC_SECRET_FILE` | Mesh identity must come from the typed Secret reference |
| `GARAGE_ADMIN_TOKEN`, `GARAGE_ADMIN_TOKEN_FILE` | Admin credential snapshots must be provable |
| `GARAGE_METRICS_TOKEN`, `GARAGE_METRICS_TOKEN_FILE` | Metrics authentication must be tied to the typed configuration |

Released objects that already contain these overrides enter a fail-closed
migration path. Follow [reserved environment migrations](../operations/upgrades.md#reserved-environment-migrations)
and the [detailed migration guide](../operations/migration.md) before removing
or changing the old entry. Do not use a broad `envFrom` source as a shortcut
for rotating the RPC, Admin, or metrics credentials.
