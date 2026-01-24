# Gateway Cluster Mode Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `gateway: true` mode to GarageCluster so users can easily deploy gateway-only clusters that connect to storage clusters.

**Architecture:** Gateway clusters create a Deployment (not StatefulSet) with no PVCs, connect to a storage cluster via `connectTo` field, and register all pods as gateway nodes (capacity=null) in the shared layout. This eliminates the need for GarageNode CRD for the common gateway use case.

**Tech Stack:** Go, Kubernetes controller-runtime, Ginkgo/Gomega tests

---

## Overview

### User Experience (Before vs After)

**Before (Complex):**
```yaml
# 1. Create storage cluster
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: garage-storage
spec:
  replicas: 3
  storage:
    data:
      size: 100Gi
---
# 2. Manually create Deployment for gateway pods
apiVersion: apps/v1
kind: Deployment
metadata:
  name: garage-gateway
spec:
  replicas: 2
  # ... lots of manual config
---
# 3. Create GarageNode for each gateway pod
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageNode
metadata:
  name: gateway-0
spec:
  clusterRef:
    name: garage-storage
  gateway: true
  zone: edge
  podSelector:
    name: garage-gateway-xxx
```

**After (Simple):**
```yaml
# 1. Create storage cluster
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: garage-storage
spec:
  replicas: 3
  storage:
    data:
      size: 100Gi
---
# 2. Create gateway cluster (that's it!)
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: garage-gateway
spec:
  replicas: 5
  gateway: true
  connectTo:
    clusterRef:
      name: garage-storage
```

---

## Task 1: Add Gateway Fields to GarageClusterSpec

**Files:**
- Modify: `api/v1alpha1/garagecluster_types.go`
- Test: `api/v1alpha1/webhook_test.go`

**Step 1: Add Gateway and ConnectTo fields**

Add these fields to `GarageClusterSpec` after line 192 (after `Workers`):

```go
// Gateway marks this cluster as a gateway-only cluster.
// Gateway clusters don't store data - they only handle API requests.
// When true:
// - Creates a Deployment instead of StatefulSet (no PVCs)
// - Storage config is ignored
// - Pods are registered as gateway nodes in the layout (capacity=null)
// - Must specify connectTo to reference a storage cluster
// +optional
Gateway bool `json:"gateway,omitempty"`

// ConnectTo specifies the storage cluster this gateway cluster connects to.
// Required when gateway=true. The gateway cluster will:
// - Use the same RPC secret as the storage cluster
// - Connect to the storage cluster's nodes
// - Register its pods as gateway nodes in the storage cluster's layout
// +optional
ConnectTo *ConnectToConfig `json:"connectTo,omitempty"`
```

**Step 2: Add ConnectToConfig struct**

Add after `RemoteClusterConnection` struct (~line 894):

```go
// ConnectToConfig specifies how a gateway cluster connects to a storage cluster
type ConnectToConfig struct {
	// ClusterRef references a GarageCluster in the same namespace
	// The gateway will use this cluster's RPC secret and connect to its nodes
	// +optional
	ClusterRef *ClusterReference `json:"clusterRef,omitempty"`

	// RPCSecretRef references a shared RPC secret (for cross-namespace or external clusters)
	// If clusterRef is specified, this is ignored (uses the referenced cluster's secret)
	// +optional
	RPCSecretRef *corev1.SecretKeySelector `json:"rpcSecretRef,omitempty"`

	// BootstrapPeers are the initial peers to connect to (for external storage clusters)
	// Format: "<node_public_key>@<ip_or_hostname>:<port>"
	// +optional
	BootstrapPeers []string `json:"bootstrapPeers,omitempty"`

	// AdminAPIEndpoint is the admin API endpoint for discovering nodes and registering gateways
	// Required if clusterRef is not in the same namespace
	// Example: "http://garage-storage.other-namespace:3903"
	// +optional
	AdminAPIEndpoint string `json:"adminApiEndpoint,omitempty"`

	// AdminTokenSecretRef references the admin token for the storage cluster
	// If clusterRef is specified and in same namespace, uses that cluster's token
	// +optional
	AdminTokenSecretRef *corev1.SecretKeySelector `json:"adminTokenSecretRef,omitempty"`
}
```

**Step 3: Run make generate**

```bash
make generate && make manifests
```
Expected: CRD updated, no errors

**Step 4: Commit**

```bash
git add api/v1alpha1/garagecluster_types.go config/crd/bases/
git commit -m "feat: add Gateway and ConnectTo fields to GarageClusterSpec"
```

---

## Task 2: Add Webhook Validation for Gateway Mode

**Files:**
- Modify: `api/v1alpha1/garagecluster_webhook.go`
- Test: `api/v1alpha1/webhook_test.go`

**Step 1: Write the failing test**

Add to `api/v1alpha1/webhook_test.go`:

```go
var _ = Describe("GarageCluster Webhook Gateway Validation", func() {
	Context("When validating gateway clusters", func() {
		It("should reject gateway=true without connectTo", func() {
			cluster := &GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
				Spec: GarageClusterSpec{
					Gateway:  true,
					Replicas: 2,
					Replication: ReplicationConfig{Factor: 3},
				},
			}
			_, err := cluster.ValidateCreate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("connectTo is required when gateway is true"))
		})

		It("should reject connectTo without gateway=true", func() {
			cluster := &GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "test-storage", Namespace: "default"},
				Spec: GarageClusterSpec{
					Replicas:    3,
					Replication: ReplicationConfig{Factor: 3},
					ConnectTo: &ConnectToConfig{
						ClusterRef: &ClusterReference{Name: "other-cluster"},
					},
				},
			}
			_, err := cluster.ValidateCreate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("connectTo can only be specified when gateway is true"))
		})

		It("should reject gateway=true with storage config", func() {
			size := resource.MustParse("100Gi")
			cluster := &GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
				Spec: GarageClusterSpec{
					Gateway:  true,
					Replicas: 2,
					Replication: ReplicationConfig{Factor: 3},
					ConnectTo: &ConnectToConfig{
						ClusterRef: &ClusterReference{Name: "storage-cluster"},
					},
					Storage: StorageConfig{
						Data: &DataStorageConfig{Size: &size},
					},
				},
			}
			_, err := cluster.ValidateCreate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("storage cannot be specified for gateway clusters"))
		})

		It("should accept valid gateway cluster", func() {
			cluster := &GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
				Spec: GarageClusterSpec{
					Gateway:  true,
					Replicas: 2,
					Replication: ReplicationConfig{Factor: 3},
					ConnectTo: &ConnectToConfig{
						ClusterRef: &ClusterReference{Name: "storage-cluster"},
					},
				},
			}
			_, err := cluster.ValidateCreate()
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
```

**Step 2: Run test to verify it fails**

```bash
go test ./api/v1alpha1/... -v -run "Gateway"
```
Expected: FAIL (validation not implemented)

**Step 3: Add validation logic**

In `api/v1alpha1/garagecluster_webhook.go`, add to `validateGarageCluster()`:

```go
// Validate gateway mode
if r.Spec.Gateway {
	if r.Spec.ConnectTo == nil {
		allErrs = append(allErrs, field.Required(
			field.NewPath("spec").Child("connectTo"),
			"connectTo is required when gateway is true",
		))
	}
	// Gateway clusters should not have storage config
	if r.Spec.Storage.Data != nil && r.Spec.Storage.Data.Size != nil {
		allErrs = append(allErrs, field.Forbidden(
			field.NewPath("spec").Child("storage"),
			"storage cannot be specified for gateway clusters",
		))
	}
} else {
	// Non-gateway clusters should not have connectTo
	if r.Spec.ConnectTo != nil {
		allErrs = append(allErrs, field.Forbidden(
			field.NewPath("spec").Child("connectTo"),
			"connectTo can only be specified when gateway is true",
		))
	}
}

// Validate connectTo config
if r.Spec.ConnectTo != nil {
	if r.Spec.ConnectTo.ClusterRef == nil &&
	   r.Spec.ConnectTo.RPCSecretRef == nil &&
	   len(r.Spec.ConnectTo.BootstrapPeers) == 0 {
		allErrs = append(allErrs, field.Required(
			field.NewPath("spec").Child("connectTo"),
			"must specify clusterRef, rpcSecretRef, or bootstrapPeers",
		))
	}
}
```

**Step 4: Run test to verify it passes**

```bash
go test ./api/v1alpha1/... -v -run "Gateway"
```
Expected: PASS

**Step 5: Commit**

```bash
git add api/v1alpha1/garagecluster_webhook.go api/v1alpha1/webhook_test.go
git commit -m "feat: add webhook validation for gateway mode"
```

---

## Task 3: Create Deployment for Gateway Clusters

**Files:**
- Modify: `internal/controller/garagecluster_controller.go`
- Test: `internal/controller/garagecluster_controller_test.go`

**Step 1: Write the failing test**

Add to `internal/controller/garagecluster_controller_test.go`:

```go
Context("When creating a gateway cluster", func() {
	const gatewayName = "test-gateway"
	const storageName = "test-storage"
	var gatewayNN, storageNN types.NamespacedName

	BeforeEach(func() {
		gatewayNN = types.NamespacedName{Name: gatewayName, Namespace: "default"}
		storageNN = types.NamespacedName{Name: storageName, Namespace: "default"}

		// Create storage cluster first
		storageCluster := &garagev1alpha1.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: storageName, Namespace: "default"},
			Spec: garagev1alpha1.GarageClusterSpec{
				Replicas:    3,
				Replication: garagev1alpha1.ReplicationConfig{Factor: 3},
			},
		}
		Expect(k8sClient.Create(ctx, storageCluster)).To(Succeed())
	})

	AfterEach(func() {
		// Cleanup
		gateway := &garagev1alpha1.GarageCluster{}
		if err := k8sClient.Get(ctx, gatewayNN, gateway); err == nil {
			gateway.Finalizers = nil
			_ = k8sClient.Update(ctx, gateway)
			_ = k8sClient.Delete(ctx, gateway)
		}
		storage := &garagev1alpha1.GarageCluster{}
		if err := k8sClient.Get(ctx, storageNN, storage); err == nil {
			storage.Finalizers = nil
			_ = k8sClient.Update(ctx, storage)
			_ = k8sClient.Delete(ctx, storage)
		}
		_ = k8sClient.Delete(ctx, &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: gatewayName, Namespace: "default"},
		})
	})

	It("should create a Deployment instead of StatefulSet", func() {
		By("Creating the gateway GarageCluster")
		gateway := &garagev1alpha1.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: gatewayName, Namespace: "default"},
			Spec: garagev1alpha1.GarageClusterSpec{
				Gateway:     true,
				Replicas:    2,
				Replication: garagev1alpha1.ReplicationConfig{Factor: 3},
				ConnectTo: &garagev1alpha1.ConnectToConfig{
					ClusterRef: &garagev1alpha1.ClusterReference{Name: storageName},
				},
			},
		}
		Expect(k8sClient.Create(ctx, gateway)).To(Succeed())

		By("Reconciling the gateway cluster")
		reconciler := &GarageClusterReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: gatewayNN})
		Expect(err).NotTo(HaveOccurred())

		By("Verifying a Deployment was created (not StatefulSet)")
		deployment := &appsv1.Deployment{}
		Eventually(func() error {
			return k8sClient.Get(ctx, gatewayNN, deployment)
		}, timeout, interval).Should(Succeed())
		Expect(*deployment.Spec.Replicas).To(Equal(int32(2)))

		By("Verifying no StatefulSet was created")
		sts := &appsv1.StatefulSet{}
		err = k8sClient.Get(ctx, gatewayNN, sts)
		Expect(errors.IsNotFound(err)).To(BeTrue())

		By("Verifying no PVCs in the Deployment")
		Expect(deployment.Spec.Template.Spec.Volumes).NotTo(ContainElement(
			HaveField("PersistentVolumeClaim", Not(BeNil())),
		))
	})
})
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/controller/... -v -run "gateway cluster"
```
Expected: FAIL (creates StatefulSet, not Deployment)

**Step 3: Add reconcileDeployment function**

Add new function in `internal/controller/garagecluster_controller.go`:

```go
// reconcileDeployment creates/updates a Deployment for gateway clusters.
// Gateway clusters don't need persistent storage, so we use a Deployment instead of StatefulSet.
func (r *GarageClusterReconciler) reconcileDeployment(ctx context.Context, cluster *garagev1alpha1.GarageCluster, configHash string) error {
	log := log.FromContext(ctx)
	deployName := cluster.Name

	// Build pod template (similar to StatefulSet but no PVCs)
	labels := map[string]string{
		"app.kubernetes.io/name":       "garage",
		"app.kubernetes.io/instance":   cluster.Name,
		"app.kubernetes.io/component":  "gateway",
		"app.kubernetes.io/managed-by": "garage-operator",
	}

	// Merge with user labels
	for k, v := range cluster.Spec.PodLabels {
		labels[k] = v
	}

	podAnnotations := map[string]string{
		"garage.rajsingh.info/config-hash": configHash,
	}
	for k, v := range cluster.Spec.PodAnnotations {
		podAnnotations[k] = v
	}

	// Build container ports (same as storage cluster)
	ports := r.buildContainerPorts(cluster)

	// Build volumes - config only, no data/metadata PVCs
	volumes := []corev1.Volume{
		{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: cluster.Name + "-config",
					},
				},
			},
		},
	}

	// Add RPC secret volume
	rpcSecretName := r.getRPCSecretName(cluster)
	volumes = append(volumes, corev1.Volume{
		Name: "rpc-secret",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: rpcSecretName,
			},
		},
	})

	// Add admin token volume if configured
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.AdminTokenSecretRef != nil {
		volumes = append(volumes, corev1.Volume{
			Name: "admin-token",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: cluster.Spec.Admin.AdminTokenSecretRef.Name,
				},
			},
		})
	}

	volumeMounts := []corev1.VolumeMount{
		{Name: "config", MountPath: "/etc/garage", ReadOnly: true},
		{Name: "rpc-secret", MountPath: "/secrets/rpc", ReadOnly: true},
	}
	if cluster.Spec.Admin != nil && cluster.Spec.Admin.AdminTokenSecretRef != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "admin-token",
			MountPath: "/secrets/admin",
			ReadOnly:  true,
		})
	}

	// Gateway needs ephemeral storage for metadata (not persisted)
	volumes = append(volumes, corev1.Volume{
		Name: "metadata",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	})
	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      "metadata",
		MountPath: "/var/lib/garage/meta",
	})

	// Build environment variables
	env := r.buildEnvironmentVariables(cluster)

	replicas := cluster.Spec.Replicas
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deployName,
			Namespace: cluster.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      labels,
					Annotations: podAnnotations,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: cluster.Spec.ServiceAccountName,
					SecurityContext:    cluster.Spec.SecurityContext,
					NodeSelector:       cluster.Spec.NodeSelector,
					Tolerations:        cluster.Spec.Tolerations,
					Affinity:           cluster.Spec.Affinity,
					PriorityClassName:  cluster.Spec.PriorityClassName,
					ImagePullSecrets:   cluster.Spec.ImagePullSecrets,
					Containers: []corev1.Container{
						{
							Name:            "garage",
							Image:           r.getImage(cluster),
							ImagePullPolicy: cluster.Spec.ImagePullPolicy,
							Command:         []string{"/garage", "server", "-c", "/etc/garage/garage.toml"},
							Ports:           ports,
							VolumeMounts:    volumeMounts,
							Resources:       cluster.Spec.Resources,
							SecurityContext: cluster.Spec.ContainerSecurityContext,
							Env:             env,
						},
					},
					Volumes:                       volumes,
					TopologySpreadConstraints:     cluster.Spec.TopologySpreadConstraints,
				},
			},
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(cluster, deploy, r.Scheme); err != nil {
		return fmt.Errorf("failed to set owner reference: %w", err)
	}

	// Create or update
	existing := &appsv1.Deployment{}
	err := r.Get(ctx, types.NamespacedName{Name: deployName, Namespace: cluster.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Creating Deployment for gateway cluster", "name", deployName)
			return r.Create(ctx, deploy)
		}
		return err
	}

	// Check if update needed
	existingConfigHash := existing.Spec.Template.Annotations["garage.rajsingh.info/config-hash"]
	if existingConfigHash != configHash || *existing.Spec.Replicas != replicas {
		log.Info("Updating Deployment", "name", deployName)
		existing.Spec = deploy.Spec
		return r.Update(ctx, existing)
	}

	log.V(1).Info("Deployment is up to date", "name", deployName)
	return nil
}

// getRPCSecretName returns the RPC secret name for the cluster.
// For gateway clusters with clusterRef, uses the referenced cluster's secret.
func (r *GarageClusterReconciler) getRPCSecretName(cluster *garagev1alpha1.GarageCluster) string {
	if cluster.Spec.Gateway && cluster.Spec.ConnectTo != nil {
		if cluster.Spec.ConnectTo.ClusterRef != nil {
			// Use the storage cluster's RPC secret
			return cluster.Spec.ConnectTo.ClusterRef.Name + "-rpc-secret"
		}
		if cluster.Spec.ConnectTo.RPCSecretRef != nil {
			return cluster.Spec.ConnectTo.RPCSecretRef.Name
		}
	}
	if cluster.Spec.Network.RPCSecretRef != nil {
		return cluster.Spec.Network.RPCSecretRef.Name
	}
	return cluster.Name + "-rpc-secret"
}
```

**Step 4: Modify Reconcile to choose Deployment vs StatefulSet**

In the `Reconcile` function, change the StatefulSet reconciliation:

```go
// Create or update workload (Deployment for gateway, StatefulSet for storage)
if cluster.Spec.Gateway {
	if err := r.reconcileDeployment(ctx, cluster, configHash); err != nil {
		return ctrl.Result{}, err
	}
} else {
	if err := r.reconcileStatefulSet(ctx, cluster, configHash); err != nil {
		return ctrl.Result{}, err
	}
}
```

**Step 5: Run test to verify it passes**

```bash
go test ./internal/controller/... -v -run "gateway cluster"
```
Expected: PASS

**Step 6: Commit**

```bash
git add internal/controller/garagecluster_controller.go internal/controller/garagecluster_controller_test.go
git commit -m "feat: create Deployment for gateway clusters"
```

---

## Task 4: Generate Gateway-Specific TOML Config

**Files:**
- Modify: `internal/controller/garagecluster_controller.go`
- Test: `internal/controller/garagecluster_controller_test.go`

**Step 1: Write the failing test**

```go
It("should generate config without data_dir for gateway clusters", func() {
	gateway := &garagev1alpha1.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway-config-test", Namespace: "default"},
		Spec: garagev1alpha1.GarageClusterSpec{
			Gateway:     true,
			Replicas:    2,
			Replication: garagev1alpha1.ReplicationConfig{Factor: 3},
			ConnectTo: &garagev1alpha1.ConnectToConfig{
				ClusterRef: &garagev1alpha1.ClusterReference{Name: storageName},
			},
		},
	}

	reconciler := &GarageClusterReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	config := reconciler.generateGarageConfig(gateway)

	// Gateway config should NOT have data_dir
	Expect(config).NotTo(ContainSubstring("data_dir"))
	// But should have metadata_dir (for routing tables)
	Expect(config).To(ContainSubstring("metadata_dir"))
})
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/controller/... -v -run "config without data_dir"
```
Expected: FAIL

**Step 3: Modify generateGarageConfig for gateway mode**

In `generateGarageConfig()`, add conditional for data directory:

```go
// Data directory - only for storage clusters
if !cluster.Spec.Gateway {
	dataDir := "/var/lib/garage/data"
	// ... existing data_dir logic
	config.WriteString(fmt.Sprintf("data_dir = \"%s\"\n", dataDir))
}
```

**Step 4: Run test to verify it passes**

```bash
go test ./internal/controller/... -v -run "config without data_dir"
```
Expected: PASS

**Step 5: Commit**

```bash
git add internal/controller/garagecluster_controller.go internal/controller/garagecluster_controller_test.go
git commit -m "feat: generate gateway-specific TOML config (no data_dir)"
```

---

## Task 5: Register Gateway Pods in Layout

**Files:**
- Modify: `internal/controller/garagecluster_controller.go`
- Test: `internal/controller/garagecluster_controller_test.go`

**Step 1: Write the failing test**

```go
It("should register gateway pods with capacity=null in layout", func() {
	// This test requires a running Garage cluster to verify layout
	// For unit tests, we verify the layout update request is correct
	Skip("Requires e2e test with real Garage cluster")
})
```

**Step 2: Add gateway layout registration logic**

Modify `assignNewNodesToLayout()` to handle gateway clusters:

```go
// For gateway clusters, assign with nil capacity
if cluster.Spec.Gateway {
	role := &garage.LayoutRole{
		ID:       node.ID,
		Zone:     zone,
		Capacity: nil, // nil = gateway node
		Tags:     tags,
	}
	newRoles = append(newRoles, *role)
} else {
	// Existing storage node logic
	capacity := r.calculateNodeCapacity(cluster)
	role := &garage.LayoutRole{
		ID:       node.ID,
		Zone:     zone,
		Capacity: &capacity,
		Tags:     tags,
	}
	newRoles = append(newRoles, *role)
}
```

**Step 3: Commit**

```bash
git add internal/controller/garagecluster_controller.go
git commit -m "feat: register gateway pods with null capacity in layout"
```

---

## Task 6: Connect Gateway to Storage Cluster

**Files:**
- Modify: `internal/controller/garagecluster_controller.go`
- Test: `internal/controller/garagecluster_controller_test.go`

**Step 1: Add reconcileGatewayConnection function**

```go
// reconcileGatewayConnection connects a gateway cluster to its storage cluster.
// It discovers the storage cluster's nodes and connects the gateway nodes to them.
func (r *GarageClusterReconciler) reconcileGatewayConnection(ctx context.Context, cluster *garagev1alpha1.GarageCluster) error {
	log := log.FromContext(ctx)

	if !cluster.Spec.Gateway || cluster.Spec.ConnectTo == nil {
		return nil
	}

	// Get the storage cluster
	if cluster.Spec.ConnectTo.ClusterRef != nil {
		storageCluster := &garagev1alpha1.GarageCluster{}
		storageNN := types.NamespacedName{
			Name:      cluster.Spec.ConnectTo.ClusterRef.Name,
			Namespace: cluster.Namespace,
		}
		if cluster.Spec.ConnectTo.ClusterRef.Namespace != "" {
			storageNN.Namespace = cluster.Spec.ConnectTo.ClusterRef.Namespace
		}

		if err := r.Get(ctx, storageNN, storageCluster); err != nil {
			return fmt.Errorf("failed to get storage cluster: %w", err)
		}

		// Get storage cluster's admin API client
		storageClient, err := r.GetGarageClient(ctx, storageCluster)
		if err != nil {
			return fmt.Errorf("failed to get storage cluster client: %w", err)
		}

		// Get storage cluster status to discover nodes
		status, err := storageClient.GetClusterStatus(ctx)
		if err != nil {
			return fmt.Errorf("failed to get storage cluster status: %w", err)
		}

		// Connect gateway to each storage node
		for _, node := range status.Nodes {
			if node.Addr != nil && *node.Addr != "" {
				peer := fmt.Sprintf("%s@%s", node.ID, *node.Addr)
				log.V(1).Info("Connecting gateway to storage node", "peer", peer)
				if err := storageClient.ConnectNode(ctx, peer); err != nil {
					log.Error(err, "Failed to connect to storage node", "peer", peer)
					// Continue with other nodes
				}
			}
		}
	}

	return nil
}
```

**Step 2: Call from Reconcile**

Add after workload reconciliation:

```go
// For gateway clusters, connect to storage cluster
if cluster.Spec.Gateway {
	if err := r.reconcileGatewayConnection(ctx, cluster); err != nil {
		log.Error(err, "Failed to connect gateway to storage cluster")
		// Don't fail reconciliation, will retry
	}
}
```

**Step 3: Commit**

```bash
git add internal/controller/garagecluster_controller.go
git commit -m "feat: connect gateway cluster to storage cluster"
```

---

## Task 7: Add Controller Watch for Deployments

**Files:**
- Modify: `internal/controller/garagecluster_controller.go`

**Step 1: Add Deployment to SetupWithManager**

Modify `SetupWithManager`:

```go
func (r *GarageClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&garagev1alpha1.GarageCluster{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&appsv1.Deployment{}). // Add this line
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
```

**Step 2: Commit**

```bash
git add internal/controller/garagecluster_controller.go
git commit -m "feat: add Deployment watch to controller"
```

---

## Task 8: Update Status for Gateway Clusters

**Files:**
- Modify: `internal/controller/garagecluster_controller.go`

**Step 1: Update updateStatus for Deployment**

Modify `updateStatus()` to check Deployment for gateway clusters:

```go
func (r *GarageClusterReconciler) updateStatus(ctx context.Context, cluster *garagev1alpha1.GarageCluster) error {
	var readyReplicas int32

	if cluster.Spec.Gateway {
		// Get Deployment status
		deploy := &appsv1.Deployment{}
		if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, deploy); err != nil {
			if !errors.IsNotFound(err) {
				return err
			}
		} else {
			readyReplicas = deploy.Status.ReadyReplicas
		}
	} else {
		// Get StatefulSet status
		sts := &appsv1.StatefulSet{}
		if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, sts); err != nil {
			if !errors.IsNotFound(err) {
				return err
			}
		} else {
			readyReplicas = sts.Status.ReadyReplicas
		}
	}

	cluster.Status.ReadyReplicas = readyReplicas
	// ... rest of status update
}
```

**Step 2: Commit**

```bash
git add internal/controller/garagecluster_controller.go
git commit -m "feat: update status from Deployment for gateway clusters"
```

---

## Task 9: Handle Gateway Cluster Deletion

**Files:**
- Modify: `internal/controller/garagecluster_controller.go`

**Step 1: Update handleDeletion for Deployment cleanup**

Modify the deletion handling to clean up Deployment:

```go
func (r *GarageClusterReconciler) handleDeletion(ctx context.Context, cluster *garagev1alpha1.GarageCluster) error {
	log := log.FromContext(ctx)

	// Delete workload based on type
	if cluster.Spec.Gateway {
		deploy := &appsv1.Deployment{}
		if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, deploy); err == nil {
			log.Info("Deleting Deployment", "name", deploy.Name)
			if err := r.Delete(ctx, deploy); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete Deployment: %w", err)
			}
		}
	} else {
		sts := &appsv1.StatefulSet{}
		if err := r.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, sts); err == nil {
			log.Info("Deleting StatefulSet", "name", sts.Name)
			if err := r.Delete(ctx, sts); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete StatefulSet: %w", err)
			}
		}
	}

	// ... rest of cleanup (services, configmap, etc.)
}
```

**Step 2: Commit**

```bash
git add internal/controller/garagecluster_controller.go
git commit -m "feat: handle gateway cluster deletion (Deployment cleanup)"
```

---

## Task 10: Add E2E Tests

**Files:**
- Modify: `test/e2e/e2e_test.go`

**Step 1: Add gateway e2e test**

```go
var _ = Describe("Gateway Cluster E2E", Label("e2e"), func() {
	Context("When deploying a gateway cluster", func() {
		It("should connect to storage cluster and handle S3 requests", func() {
			By("Creating a storage cluster")
			// ... create storage cluster

			By("Creating a gateway cluster")
			gateway := &garagev1alpha1.GarageCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "garage-gateway", Namespace: namespace},
				Spec: garagev1alpha1.GarageClusterSpec{
					Gateway:     true,
					Replicas:    2,
					Replication: garagev1alpha1.ReplicationConfig{Factor: 3},
					ConnectTo: &garagev1alpha1.ConnectToConfig{
						ClusterRef: &garagev1alpha1.ClusterReference{Name: "garage-storage"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())

			By("Waiting for gateway pods to be ready")
			Eventually(func() int32 {
				g := &garagev1alpha1.GarageCluster{}
				_ = k8sClient.Get(ctx, types.NamespacedName{Name: "garage-gateway", Namespace: namespace}, g)
				return g.Status.ReadyReplicas
			}, timeout, interval).Should(Equal(int32(2)))

			By("Verifying gateway is in layout")
			// Check layout shows gateway nodes with null capacity

			By("Verifying S3 requests through gateway work")
			// Create bucket, upload object through gateway endpoint
		})
	})
})
```

**Step 2: Commit**

```bash
git add test/e2e/e2e_test.go
git commit -m "test: add gateway cluster e2e tests"
```

---

## Task 11: Update Documentation

**Files:**
- Modify: `CLAUDE.md`
- Create: `docs/gateway-clusters.md`

**Step 1: Update CLAUDE.md**

Add gateway cluster section to the Quick Reference.

**Step 2: Create gateway documentation**

```markdown
# Gateway Clusters

Gateway clusters provide a simple way to deploy Garage gateway nodes that handle
S3 API requests without storing data.

## Quick Start

\`\`\`yaml
# Storage cluster
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: garage-storage
spec:
  replicas: 3
  storage:
    data:
      size: 100Gi

---
# Gateway cluster
apiVersion: garage.rajsingh.info/v1alpha1
kind: GarageCluster
metadata:
  name: garage-gateway
spec:
  gateway: true
  replicas: 5
  connectTo:
    clusterRef:
      name: garage-storage
\`\`\`

## When to Use Gateway Clusters

- **Network efficiency**: Place gateways closer to clients
- **Independent scaling**: Scale gateways based on traffic, storage based on data
- **Resource optimization**: Gateways need CPU/memory, not disk
- **Edge deployment**: Run lightweight gateways at edge locations

## Configuration Options

### connectTo.clusterRef
Reference a GarageCluster in the same namespace:
\`\`\`yaml
connectTo:
  clusterRef:
    name: my-storage-cluster
\`\`\`

### connectTo.rpcSecretRef
Use a shared RPC secret (for cross-namespace or external clusters):
\`\`\`yaml
connectTo:
  rpcSecretRef:
    name: shared-rpc-secret
    key: rpc-secret
  bootstrapPeers:
    - "abc123...@storage-1.example.com:3901"
\`\`\`
```

**Step 3: Commit**

```bash
git add CLAUDE.md docs/gateway-clusters.md
git commit -m "docs: add gateway cluster documentation"
```

---

## Summary

| Task | Description | Estimated Complexity |
|------|-------------|---------------------|
| 1 | Add Gateway and ConnectTo fields | Low |
| 2 | Add webhook validation | Low |
| 3 | Create Deployment for gateways | Medium |
| 4 | Generate gateway-specific TOML | Low |
| 5 | Register gateway pods in layout | Medium |
| 6 | Connect gateway to storage | Medium |
| 7 | Add Deployment watch | Low |
| 8 | Update status for gateways | Low |
| 9 | Handle gateway deletion | Low |
| 10 | Add E2E tests | Medium |
| 11 | Update documentation | Low |

---

**Plan complete and saved to `docs/plans/2026-01-23-gateway-cluster-mode.md`. Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**
