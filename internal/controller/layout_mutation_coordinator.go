/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// errLayoutMutationPending is a transient safety wait, not a failed resource.
// Callers should surface Pending/Deleting and requeue without consuming a
// finalizer retry budget. It is the same sentinel as garage.ErrLayoutPending so
// a layout write refused on a Follower site (garage.ErrLayoutWritesDisabled)
// takes every existing pending branch instead of becoming a failure.
var errLayoutMutationPending = garage.ErrLayoutPending

// LayoutMutationCoordinator serializes every layout writer in one active
// controller-manager process by the GarageCluster whose layout it mutates.
// The Helm chart enables controller-runtime leader election by default, so a
// single coordinator covers all reconcilers in the active manager while leader
// election prevents a second manager from writing concurrently.
//
// This deliberately does not claim to be a lock across Kubernetes clusters.
// Federated sites must still perform topology changes one site at a time.
type LayoutMutationCoordinator struct {
	mu                    sync.Mutex
	held                  map[types.NamespacedName]struct{}
	nodeLocalPoolRollouts map[types.NamespacedName]nodeLocalPoolRolloutMarker
	storageDrains         map[types.NamespacedName]storageDrainMarker
}

type nodeLocalPoolRolloutMarker struct {
	ownerUID        types.UID
	source          types.NamespacedName
	sourceUID       types.UID
	statusConfirmed bool
}

type storageDrainMarker struct {
	ownerUID        types.UID
	actorUID        types.UID
	transactionID   string
	targetHash      string
	statusConfirmed bool
}

func (m storageDrainMarker) matches(other storageDrainMarker) bool {
	return m.ownerUID == other.ownerUID && m.actorUID == other.actorUID &&
		m.transactionID == other.transactionID && m.targetHash == other.targetHash
}

type storageDrainActor struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	UID        types.UID
}

func NewLayoutMutationCoordinator() *LayoutMutationCoordinator {
	return &LayoutMutationCoordinator{
		held:                  make(map[types.NamespacedName]struct{}),
		nodeLocalPoolRollouts: make(map[types.NamespacedName]nodeLocalPoolRolloutMarker),
		storageDrains:         make(map[types.NamespacedName]storageDrainMarker),
	}
}

func storageDrainActorForCluster(cluster *garagev1beta2.GarageCluster) storageDrainActor {
	if cluster == nil {
		return storageDrainActor{}
	}
	return storageDrainActor{
		APIVersion: garagev1beta2.GroupVersion.String(),
		Kind:       kindGarageCluster,
		Namespace:  cluster.Namespace,
		Name:       cluster.Name,
		UID:        cluster.UID,
	}
}

func storageDrainActorForNode(node *garagev1beta1.GarageNode) storageDrainActor {
	if node == nil {
		return storageDrainActor{}
	}
	return storageDrainActor{
		APIVersion: garagev1beta1.GroupVersion.String(),
		Kind:       kindGarageNode,
		Namespace:  node.Namespace,
		Name:       node.Name,
		UID:        node.UID,
	}
}

func storageDrainActorMatches(status *garagev1beta2.StorageDrainStatus, actor storageDrainActor) bool {
	return status != nil && actor.UID != "" &&
		status.Actor.APIVersion == actor.APIVersion &&
		status.Actor.Kind == actor.Kind &&
		status.Actor.Namespace == actor.Namespace &&
		status.Actor.Name == actor.Name &&
		status.Actor.UID == string(actor.UID)
}

// BeginStorageDrain closes the publication gap before a drain intent is made
// durable. ConfirmStorageDrain distinguishes that provisional head from the
// status-clear -> EndStorageDrain crash tail. A different actor, transaction,
// or target revision can never replace the marker through this method.
func (c *LayoutMutationCoordinator) BeginStorageDrain(
	key types.NamespacedName,
	ownerUID, actorUID types.UID,
	transactionID, targetHash string,
) bool {
	if c == nil {
		return true
	}
	marker := storageDrainMarker{
		ownerUID: ownerUID, actorUID: actorUID,
		transactionID: transactionID, targetHash: targetHash,
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.storageDrains == nil {
		c.storageDrains = make(map[types.NamespacedName]storageDrainMarker)
	}
	if existing, found := c.storageDrains[key]; found {
		return existing.matches(marker)
	}
	c.storageDrains[key] = marker
	return true
}

// ConfirmStorageDrain marks the durable-status publication complete for the
// exact marker. A confirmed marker with no matching status in an authoritative
// API read is a recoverable status-clear -> in-memory-End crash tail.
func (c *LayoutMutationCoordinator) ConfirmStorageDrain(
	key types.NamespacedName,
	ownerUID, actorUID types.UID,
	transactionID, targetHash string,
) bool {
	if c == nil {
		return true
	}
	wanted := storageDrainMarker{
		ownerUID: ownerUID, actorUID: actorUID,
		transactionID: transactionID, targetHash: targetHash,
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, found := c.storageDrains[key]
	if !found || !existing.matches(wanted) {
		return false
	}
	existing.statusConfirmed = true
	c.storageDrains[key] = existing
	return true
}

// AdvanceStorageDrain changes only the target revision of the exact active
// transaction. Callers hold the layout mutex and invoke this after the status
// CAS succeeds, before releasing the layout critical section.
func (c *LayoutMutationCoordinator) AdvanceStorageDrain(
	key types.NamespacedName,
	ownerUID, actorUID types.UID,
	transactionID, previousTargetHash, nextTargetHash string,
) bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, found := c.storageDrains[key]
	if !found || existing.ownerUID != ownerUID || existing.actorUID != actorUID ||
		existing.transactionID != transactionID || existing.targetHash != previousTargetHash {
		return false
	}
	existing.targetHash = nextTargetHash
	c.storageDrains[key] = existing
	return true
}

func (c *LayoutMutationCoordinator) EndStorageDrain(
	key types.NamespacedName,
	ownerUID, actorUID types.UID,
	transactionID, targetHash string,
) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if existing, found := c.storageDrains[key]; found &&
		existing.matches(storageDrainMarker{ownerUID: ownerUID, actorUID: actorUID, transactionID: transactionID, targetHash: targetHash}) {
		delete(c.storageDrains, key)
	}
	c.mu.Unlock()
}

// PruneConfirmedStorageDrainWithoutStatus closes the narrow tail where clearing
// status succeeded but the process stopped before EndStorageDrain ran. Callers
// may invoke it only after an authoritative API read/scan found no durable
// transaction for this canonical layout. Provisional markers are deliberately
// retained because their status write may still be in flight.
func (c *LayoutMutationCoordinator) PruneConfirmedStorageDrainWithoutStatus(
	key types.NamespacedName,
	currentOwnerUID types.UID,
) {
	if c == nil || currentOwnerUID == "" {
		return
	}
	c.mu.Lock()
	if existing, found := c.storageDrains[key]; found &&
		existing.ownerUID == currentOwnerUID && existing.statusConfirmed {
		delete(c.storageDrains, key)
	}
	c.mu.Unlock()
}

func (c *LayoutMutationCoordinator) PruneStaleStorageDrain(key types.NamespacedName, currentOwnerUID types.UID) {
	if c == nil || currentOwnerUID == "" {
		return
	}
	c.mu.Lock()
	if existing, found := c.storageDrains[key]; found && existing.ownerUID != "" && existing.ownerUID != currentOwnerUID {
		delete(c.storageDrains, key)
	}
	c.mu.Unlock()
}

func (c *LayoutMutationCoordinator) StorageDrainActive(key types.NamespacedName) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, active := c.storageDrains[key]
	return active
}

func (c *LayoutMutationCoordinator) StorageDrainActorActive(
	key types.NamespacedName,
	ownerUID, actorUID types.UID,
	transactionID, targetHash string,
) bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, active := c.storageDrains[key]
	return active && existing.matches(storageDrainMarker{
		ownerUID: ownerUID, actorUID: actorUID,
		transactionID: transactionID, targetHash: targetHash,
	})
}

// BeginNodeLocalPoolRollout records the asynchronous safety window between deleting
// an OnDelete pod and observing the replacement pod's exact Garage identity.
// The status condition persists the same state across manager restarts; this
// in-memory marker closes the interval in which another worker may still hold
// a cluster object fetched just before that status write became visible.
func (c *LayoutMutationCoordinator) BeginNodeLocalPoolRollout(
	key types.NamespacedName,
	ownerUID types.UID,
	source types.NamespacedName,
	sourceUID types.UID,
) bool {
	if c == nil {
		return true
	}
	marker := nodeLocalPoolRolloutMarker{ownerUID: ownerUID, source: source, sourceUID: sourceUID}
	if key == (types.NamespacedName{}) || ownerUID == "" || source == (types.NamespacedName{}) || sourceUID == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nodeLocalPoolRollouts == nil {
		c.nodeLocalPoolRollouts = make(map[types.NamespacedName]nodeLocalPoolRolloutMarker)
	}
	// One canonical Garage layout can have multiple Kubernetes source CRs (for
	// example a storage owner plus gateway-only clusterRef objects). A second
	// source may observe health, but it cannot replace the active transaction.
	if existing, exists := c.nodeLocalPoolRollouts[key]; exists {
		return existing.ownerUID == marker.ownerUID && existing.source == marker.source &&
			existing.sourceUID == marker.sourceUID
	}
	c.nodeLocalPoolRollouts[key] = marker
	return true
}

// ConfirmNodeLocalPoolRollout marks the cache-publication head complete only after
// status.storageRollout/ReasonStorageRollingOut is durable. It distinguishes a
// concurrent Begin->status writer from the status-clear->End crash tail.
func (c *LayoutMutationCoordinator) ConfirmNodeLocalPoolRollout(key types.NamespacedName, sourceUID types.UID) bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	marker, found := c.nodeLocalPoolRollouts[key]
	if !found || marker.sourceUID != sourceUID {
		return false
	}
	marker.statusConfirmed = true
	c.nodeLocalPoolRollouts[key] = marker
	return true
}

func (c *LayoutMutationCoordinator) EndNodeLocalPoolRollout(key types.NamespacedName, sourceUID types.UID) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if existing, exists := c.nodeLocalPoolRollouts[key]; exists && existing.sourceUID == sourceUID {
		delete(c.nodeLocalPoolRollouts, key)
	}
	c.mu.Unlock()
}

// PruneStaleNodeLocalPoolRollout drops only a marker proven to belong to a previous
// incarnation of the layout-owning GarageCluster. Namespaced names are reused;
// Kubernetes UIDs are the immutable ownership boundary. It deliberately keeps
// a same-UID marker even when a caller's status snapshot is stale because that
// short status-publication window is the reason the in-memory marker exists.
func (c *LayoutMutationCoordinator) PruneStaleNodeLocalPoolRollout(
	ctx context.Context,
	reader client.Reader,
	key types.NamespacedName,
	currentOwnerUID types.UID,
) error {
	if c == nil || currentOwnerUID == "" {
		return nil
	}
	c.mu.Lock()
	existing, found := c.nodeLocalPoolRollouts[key]
	if found && existing.ownerUID != "" && existing.ownerUID != currentOwnerUID {
		delete(c.nodeLocalPoolRollouts, key)
		found = false
	}
	c.mu.Unlock()
	if !found || reader == nil || existing.source == (types.NamespacedName{}) || existing.sourceUID == "" {
		return nil
	}
	source := &garagev1beta2.GarageCluster{}
	if err := reader.Get(ctx, existing.source, source); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("checking storage rollout marker source %s: %w", existing.source.String(), err)
		}
		c.mu.Lock()
		if current, ok := c.nodeLocalPoolRollouts[key]; ok && current == existing {
			delete(c.nodeLocalPoolRollouts, key)
		}
		c.mu.Unlock()
		return nil
	}
	if source.UID == existing.sourceUID {
		return nil
	}
	c.mu.Lock()
	if current, ok := c.nodeLocalPoolRollouts[key]; ok && current == existing {
		delete(c.nodeLocalPoolRollouts, key)
	}
	c.mu.Unlock()
	return nil
}

func (c *LayoutMutationCoordinator) NodeLocalPoolRolloutActive(key types.NamespacedName) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, active := c.nodeLocalPoolRollouts[key]
	return active
}

func (c *LayoutMutationCoordinator) NodeLocalPoolRolloutSourceActive(
	key types.NamespacedName,
	sourceUID types.UID,
) (active, statusConfirmed bool) {
	if c == nil {
		return false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	marker, found := c.nodeLocalPoolRollouts[key]
	return found && marker.sourceUID == sourceUID, found && marker.sourceUID == sourceUID && marker.statusConfirmed
}

// rehydrateNodeLocalPoolRolloutsForOwner discovers every durable rollout source
// that resolves to one canonical in-cluster Garage layout. This makes a
// gateway-only clusterRef transaction visible even when the referenced storage
// owner reconciles first after manager restart. More than one active source is
// an invariant violation and remains fail-closed behind the first marker.
func rehydrateNodeLocalPoolRolloutsForOwner(
	ctx context.Context,
	reader client.Reader,
	coordinator *LayoutMutationCoordinator,
	owner *garagev1beta2.GarageCluster,
	clusterScoped bool,
) error {
	if reader == nil || owner == nil {
		return nil
	}
	key := layoutOwnerKey(owner)
	ownerID := layoutRolloutOwnerID(owner)
	if err := coordinator.PruneStaleNodeLocalPoolRollout(ctx, reader, key, ownerID); err != nil {
		return err
	}
	clusters := &garagev1beta2.GarageClusterList{}
	listOptions := []client.ListOption{client.InNamespace(owner.Namespace)}
	if clusterScoped {
		listOptions = nil
	}
	if err := reader.List(ctx, clusters, listOptions...); err != nil {
		return fmt.Errorf("listing durable storage rollout sources for Garage layout %s/%s: %w", key.Namespace, key.Name, err)
	}
	sort.Slice(clusters.Items, func(i, j int) bool {
		left := types.NamespacedName{Namespace: clusters.Items[i].Namespace, Name: clusters.Items[i].Name}
		right := types.NamespacedName{Namespace: clusters.Items[j].Namespace, Name: clusters.Items[j].Name}
		return left.String() < right.String()
	})
	for i := range clusters.Items {
		source := &clusters.Items[i]
		if !nodeLocalPoolRolloutConditionActive(source) {
			continue
		}
		resolved, err := resolveGarageLayoutOwner(ctx, reader, source)
		if err != nil {
			// A source whose first canonical key already points here cannot be
			// proven unrelated, so keep this layout closed until the chain is readable.
			if layoutOwnerKey(source) == key {
				return fmt.Errorf("resolving active storage rollout source %s/%s: %w", source.Namespace, source.Name, err)
			}
			continue
		}
		if layoutOwnerKey(resolved) != key || layoutRolloutOwnerID(resolved) != ownerID {
			continue
		}
		sourceKey := types.NamespacedName{Namespace: source.Namespace, Name: source.Name}
		if !coordinator.BeginNodeLocalPoolRollout(key, ownerID, sourceKey, source.UID) {
			return fmt.Errorf(
				"multiple GarageClusters have active managed-Pod handoffs for canonical Garage layout %s/%s; source %s/%s cannot overtake the existing transaction",
				key.Namespace, key.Name, source.Namespace, source.Name,
			)
		}
		if !coordinator.ConfirmNodeLocalPoolRollout(key, source.UID) {
			return fmt.Errorf("storage rollout source %s/%s lost its canonical marker before status rehydration completed", source.Namespace, source.Name)
		}
	}
	return nil
}

// rehydrateStorageDrainsForOwner restores every durable drain marker that
// resolves to one canonical Garage layout. Most drains are stored on the
// layout-owning GarageCluster itself. Capacity-less edge gateways are the
// exception: their exact role-retirement intent is stored on the source CR,
// while the lock and immutable owner identity must belong to the fully resolved
// storage cluster or external endpoint. Scanning sources closes the
// owner-reconciles-first restart window, including multi-hop clusterRef chains.
func rehydrateStorageDrainsForOwner(
	ctx context.Context,
	reader client.Reader,
	coordinator *LayoutMutationCoordinator,
	owner *garagev1beta2.GarageCluster,
	clusterScoped bool,
	authoritative bool,
) error {
	if reader == nil || owner == nil {
		return nil
	}
	// resolveGarageLayoutOwner returns its input directly for a local storage
	// owner. Refresh that object here so the GarageNode controller never decides
	// transaction ownership from its older informer snapshot. In production the
	// caller supplies the uncached APIReader and marks it authoritative.
	freshOwner := &garagev1beta2.GarageCluster{}
	ownerObjectKey := client.ObjectKeyFromObject(owner)
	if err := reader.Get(ctx, ownerObjectKey, freshOwner); err != nil {
		return fmt.Errorf("reading canonical storage-drain owner %s: %w", ownerObjectKey.String(), err)
	}
	if owner.UID != "" && freshOwner.UID != owner.UID {
		return fmt.Errorf("canonical storage-drain owner %s was recreated", ownerObjectKey.String())
	}
	adoptGarageClusterSnapshot(owner, freshOwner)

	key := layoutOwnerKey(owner)
	ownerID := layoutRolloutOwnerID(owner)
	objectKey := types.NamespacedName{Namespace: owner.Namespace, Name: owner.Name}
	if key == objectKey {
		coordinator.PruneStaleStorageDrain(key, ownerID)
	}

	durableMarkerFound := false
	if drain := owner.Status.StorageDrain; drain != nil &&
		!completedCapacitylessGatewayRetirement(owner) {
		if !coordinator.BeginStorageDrain(
			key, ownerID, types.UID(drain.Actor.UID), drain.TransactionID, drain.TargetHash,
		) {
			return fmt.Errorf("a different storage-drain revision already owns canonical Garage layout %s/%s", key.Namespace, key.Name)
		}
		if !coordinator.ConfirmStorageDrain(
			key, ownerID, types.UID(drain.Actor.UID), drain.TransactionID, drain.TargetHash,
		) {
			return fmt.Errorf("storage-drain actor on %s/%s lost its marker during status rehydration", owner.Namespace, owner.Name)
		}
		durableMarkerFound = true
	}

	clusters := &garagev1beta2.GarageClusterList{}
	listOptions := []client.ListOption{client.InNamespace(owner.Namespace)}
	if clusterScoped {
		listOptions = nil
	}
	if err := reader.List(ctx, clusters, listOptions...); err != nil {
		return fmt.Errorf("listing durable storage-drain sources for Garage layout %s/%s: %w", key.Namespace, key.Name, err)
	}
	sort.Slice(clusters.Items, func(i, j int) bool {
		left := types.NamespacedName{Namespace: clusters.Items[i].Namespace, Name: clusters.Items[i].Name}
		right := types.NamespacedName{Namespace: clusters.Items[j].Namespace, Name: clusters.Items[j].Name}
		return left.String() < right.String()
	})
	for i := range clusters.Items {
		source := &clusters.Items[i]
		if source.UID == owner.UID && source.Namespace == owner.Namespace && source.Name == owner.Name {
			continue
		}
		proof := clusterStorageDrainProof(source.Status.StorageDrain)
		if proof == nil || proof.CompletedAt != nil || len(proof.RoleRemovalNodeIDs) == 0 ||
			len(proof.RemovedStorageNodeIDs) != 0 || !source.HasGatewayTier() ||
			source.HasStorageTier() || source.HasNodeLocalPools() ||
			!sameStorageDrainActor(proof.Actor, storageDrainActorForCluster(source)) {
			continue
		}
		resolved, err := resolveGarageLayoutOwner(ctx, reader, source)
		if err != nil {
			// A direct first-hop match might be this owner and therefore cannot be
			// ignored safely. Other broken chains remain isolated to their source.
			if layoutOwnerKey(source) == key {
				return fmt.Errorf("resolving active gateway-retirement source %s/%s: %w", source.Namespace, source.Name, err)
			}
			continue
		}
		if layoutOwnerKey(resolved) != key || layoutRolloutOwnerID(resolved) != ownerID {
			continue
		}
		if !coordinator.BeginStorageDrain(
			key, ownerID, proof.Actor.UID, proof.TransactionID, proof.TargetHash,
		) {
			return fmt.Errorf(
				"multiple storage-drain actors target canonical Garage layout %s/%s; source %s/%s cannot overtake the existing transaction",
				key.Namespace, key.Name, source.Namespace, source.Name,
			)
		}
		if !coordinator.ConfirmStorageDrain(
			key, ownerID, proof.Actor.UID, proof.TransactionID, proof.TargetHash,
		) {
			return fmt.Errorf("storage-drain source %s/%s lost its marker during status rehydration", source.Namespace, source.Name)
		}
		durableMarkerFound = true
	}
	if authoritative && !durableMarkerFound {
		coordinator.PruneConfirmedStorageDrainWithoutStatus(key, ownerID)
	}
	return nil
}

// TryAcquire returns immediately. Reconcile workers must not block behind a
// slow Admin API request; the losing worker requeues and rechecks live layout
// history after it acquires the coordinator on a later pass.
func (c *LayoutMutationCoordinator) TryAcquire(key types.NamespacedName) (release func(), acquired bool) {
	if c == nil {
		return func() {}, true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.held == nil {
		c.held = make(map[types.NamespacedName]struct{})
	}
	if _, exists := c.held[key]; exists {
		return nil, false
	}
	c.held[key] = struct{}{}
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			delete(c.held, key)
			c.mu.Unlock()
		})
	}, true
}

var defaultLayoutMutationCoordinator = NewLayoutMutationCoordinator()

func layoutOwnerKey(cluster *garagev1beta2.GarageCluster) types.NamespacedName {
	if cluster == nil {
		return types.NamespacedName{}
	}
	key := types.NamespacedName{Namespace: cluster.Namespace, Name: cluster.Name}
	// A management handle resolves a direct Admin endpoint before clusterRef, so
	// coordination must use the same precedence as GetGarageClient. Edge
	// gateways use clusterRef first (gatewayLayoutClient has that precedence).
	if !cluster.HasStorageTier() && cluster.IsManagementHandle() && cluster.Spec.ConnectTo != nil &&
		cluster.Spec.ConnectTo.AdminAPIEndpoint != "" {
		endpoint := strings.ToLower(strings.TrimRight(strings.TrimSpace(cluster.Spec.ConnectTo.AdminAPIEndpoint), "/"))
		sum := sha256.Sum256([]byte(endpoint))
		key.Namespace = "external-garage-layout"
		key.Name = fmt.Sprintf("%x", sum[:16])
	} else if !cluster.HasStorageTier() && cluster.Spec.ConnectTo != nil && cluster.Spec.ConnectTo.ClusterRef != nil {
		key.Name = cluster.Spec.ConnectTo.ClusterRef.Name
		if cluster.Spec.ConnectTo.ClusterRef.Namespace != "" {
			key.Namespace = cluster.Spec.ConnectTo.ClusterRef.Namespace
		}
	} else if !cluster.HasStorageTier() && cluster.Spec.ConnectTo != nil &&
		cluster.Spec.ConnectTo.AdminAPIEndpoint != "" {
		// Gateway and management CRs can point at the same external Garage
		// layout. Keying by their Kubernetes object would let them race inside one
		// manager, so serialize by a normalized endpoint fingerprint instead.
		endpoint := strings.ToLower(strings.TrimRight(strings.TrimSpace(cluster.Spec.ConnectTo.AdminAPIEndpoint), "/"))
		sum := sha256.Sum256([]byte(endpoint))
		key.Namespace = "external-garage-layout"
		key.Name = fmt.Sprintf("%x", sum[:16])
	}
	return key
}

// layoutRolloutOwnerID is the immutable marker identity for a canonical
// layout. In-cluster owners use their Kubernetes UID. Direct endpoint aliases
// have no shared Kubernetes object, so their already-normalized fingerprint key
// is the stable synthetic identity and prevents one alias from pruning another.
func layoutRolloutOwnerID(cluster *garagev1beta2.GarageCluster) types.UID {
	if cluster == nil {
		return ""
	}
	key := layoutOwnerKey(cluster)
	objectKey := types.NamespacedName{Namespace: cluster.Namespace, Name: cluster.Name}
	if key == objectKey {
		return cluster.UID
	}
	return types.UID("layout-key:" + key.String())
}

func (r *GarageClusterReconciler) layoutMutationCoordinator() *LayoutMutationCoordinator {
	if r.LayoutMutations != nil {
		return r.LayoutMutations
	}
	return defaultLayoutMutationCoordinator
}

func (r *GarageNodeReconciler) layoutMutationCoordinator() *LayoutMutationCoordinator {
	if r.LayoutMutations != nil {
		return r.LayoutMutations
	}
	return defaultLayoutMutationCoordinator
}

func acquireLayoutMutation(
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
) (func(), error) {
	key := layoutOwnerKey(cluster)
	if coordinator.StorageDrainActive(key) || storageDrainConditionActive(cluster) {
		return nil, fmt.Errorf(
			"%w: cluster-wide storage drain is still completing for Garage layout %s/%s",
			errLayoutMutationPending,
			key.Namespace,
			key.Name,
		)
	}
	if coordinator.NodeLocalPoolRolloutActive(key) || storageRolloutMutationBoundaryActive(cluster) {
		return nil, fmt.Errorf(
			"%w: node-local-pool pod replacement is still completing for GarageCluster %s/%s",
			errLayoutMutationPending,
			key.Namespace,
			key.Name,
		)
	}
	return acquireLayoutMutationUnconditionally(coordinator, key)
}

func acquireLayoutMutationIgnoringNodeLocalPoolRollout(
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
) (func(), error) {
	key := layoutOwnerKey(cluster)
	if coordinator.StorageDrainActive(key) || storageDrainConditionActive(cluster) {
		return nil, fmt.Errorf("%w: cannot replace a managed pod while a cluster-wide storage drain is active", errLayoutMutationPending)
	}
	return acquireLayoutMutationUnconditionally(coordinator, key)
}

// acquireLayoutMutationDuringStorageRolloutPrepare is the narrow pre-handoff
// path used by GarageNode reconciliation. A stale/Waiting rollout condition
// freezes unrelated layout writers, but GarageNodes must still be able to join
// or publish capacity/zone changes needed to make their new generation ready.
// Once an exact Pod actor is persisted (or its in-memory publication marker is
// active), this bypass closes and only that actor may mutate layout.
func acquireLayoutMutationDuringStorageRolloutPrepare(
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
) (func(), error) {
	key := layoutOwnerKey(cluster)
	if coordinator.StorageDrainActive(key) || storageDrainConditionActive(cluster) {
		return nil, fmt.Errorf("%w: cannot prepare a managed GarageNode generation while a cluster-wide storage drain is active", errLayoutMutationPending)
	}
	if coordinator.NodeLocalPoolRolloutActive(key) || nodeLocalPoolRolloutConditionActive(cluster) {
		return nil, fmt.Errorf("%w: an exact managed Pod handoff started before this GarageNode layout preparation acquired the coordinator", errLayoutMutationPending)
	}
	return acquireLayoutMutationUnconditionally(coordinator, key)
}

func acquireLayoutMutationIgnoringStorageDrain(
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
	actor storageDrainActor,
) (func(), error) {
	status := cluster.Status.StorageDrain
	if !storageDrainActorMatches(status, actor) {
		return nil, fmt.Errorf("%w: this reconciler is not the exact actor recorded in status.storageDrain", errLayoutMutationPending)
	}
	key := layoutOwnerKey(cluster)
	if coordinator.NodeLocalPoolRolloutActive(key) || storageRolloutMutationBoundaryActive(cluster) {
		return nil, fmt.Errorf("%w: cannot advance a storage drain while a managed pod replacement is active", errLayoutMutationPending)
	}
	if !coordinator.StorageDrainActorActive(
		key, layoutRolloutOwnerID(cluster), actor.UID, status.TransactionID, status.TargetHash,
	) && !coordinator.BeginStorageDrain(
		key, layoutRolloutOwnerID(cluster), actor.UID, status.TransactionID, status.TargetHash,
	) {
		return nil, fmt.Errorf("%w: a different storage-drain revision owns Garage layout %s/%s", errLayoutMutationPending, key.Namespace, key.Name)
	}
	if !coordinator.ConfirmStorageDrain(
		key, layoutRolloutOwnerID(cluster), actor.UID, status.TransactionID, status.TargetHash,
	) {
		return nil, fmt.Errorf("%w: durable storage-drain status lost its in-memory marker", errLayoutMutationPending)
	}
	return acquireLayoutMutationUnconditionally(coordinator, key)
}

// acquireCapacitylessRoleRetirementMutation is the deletion-only acquisition
// path for a gateway-only GarageCluster. A stale generation-wide rollout
// condition on the deleting edge object cannot protect storage blocks and must
// not deadlock its own role removal. Exact persisted rollout actors, canonical
// owner boundaries, and every in-memory drain/rollout marker remain exclusions.
// An exact role-only retirement drain belonging to source is the sole drain
// marker this actor may advance.
func acquireCapacitylessRoleRetirementMutation(
	coordinator *LayoutMutationCoordinator,
	owner *garagev1beta2.GarageCluster,
	source *garagev1beta2.GarageCluster,
) (func(), error) {
	key := layoutOwnerKey(owner)
	actor := storageDrainActorForCluster(source)
	proof := clusterStorageDrainProof(source.Status.StorageDrain)
	ownsRoleOnlyDrain := proof != nil && sameStorageDrainActor(proof.Actor, actor) &&
		len(proof.RemovedStorageNodeIDs) == 0
	markerOwnerID := layoutRolloutOwnerID(owner)

	if source.Status.StorageDrain != nil && !ownsRoleOnlyDrain {
		return nil, fmt.Errorf("%w: the deleting gateway has a different durable storage-drain actor", errLayoutMutationPending)
	}
	if ownsRoleOnlyDrain && !coordinator.StorageDrainActorActive(
		key, markerOwnerID, actor.UID, proof.TransactionID, proof.TargetHash,
	) && !coordinator.BeginStorageDrain(
		key, markerOwnerID, actor.UID, proof.TransactionID, proof.TargetHash,
	) {
		return nil, fmt.Errorf("%w: a different storage-drain revision owns Garage layout %s/%s", errLayoutMutationPending, key.Namespace, key.Name)
	}
	if ownsRoleOnlyDrain && !coordinator.ConfirmStorageDrain(
		key, markerOwnerID, actor.UID, proof.TransactionID, proof.TargetHash,
	) {
		return nil, fmt.Errorf("%w: durable gateway-retirement status lost its in-memory marker", errLayoutMutationPending)
	}
	if coordinator.StorageDrainActive(key) && (!ownsRoleOnlyDrain ||
		!coordinator.StorageDrainActorActive(key, markerOwnerID, actor.UID, proof.TransactionID, proof.TargetHash)) {
		return nil, fmt.Errorf("%w: a different cluster-wide storage drain owns Garage layout %s/%s", errLayoutMutationPending, key.Namespace, key.Name)
	}

	sameOwner := owner != nil && source != nil && owner.UID == source.UID &&
		owner.Namespace == source.Namespace && owner.Name == source.Name
	if !sameOwner && storageDrainConditionActive(owner) {
		return nil, fmt.Errorf("%w: the canonical Garage layout owner has an active storage drain", errLayoutMutationPending)
	}
	if coordinator.NodeLocalPoolRolloutActive(key) {
		return nil, fmt.Errorf("%w: a managed Pod handoff owns Garage layout %s/%s", errLayoutMutationPending, key.Namespace, key.Name)
	}
	if nodeLocalPoolRolloutConditionActive(source) {
		return nil, fmt.Errorf("%w: the deleting gateway has an exact durable managed Pod handoff", errLayoutMutationPending)
	}
	if sameOwner {
		// Deliberately ignore only the broad stale-generation/Waiting boundary.
		// nodeLocalPoolRolloutConditionActive above still covers a persisted actor.
	} else if storageRolloutMutationBoundaryActive(owner) {
		return nil, fmt.Errorf("%w: the canonical Garage layout owner has an active managed Pod transition", errLayoutMutationPending)
	}
	return acquireLayoutMutationUnconditionally(coordinator, key)
}

// acquireCapacitylessGarageNodeRetirementMutation is the per-node equivalent
// for Manual and unified gateway GarageNodes. The durable role-only intent is
// stored on the canonical layout owner, so that exact actor may resume while
// the marker is active. Storage drains, pod handoffs, and storage-owner rollout
// boundaries remain strict exclusions.
func acquireCapacitylessGarageNodeRetirementMutation(
	coordinator *LayoutMutationCoordinator,
	owner *garagev1beta2.GarageCluster,
	node *garagev1beta1.GarageNode,
) (func(), error) {
	if owner == nil || node == nil || !node.Spec.Gateway {
		return nil, fmt.Errorf("%w: capacity-less GarageNode retirement requires a gateway actor and canonical owner", errLayoutMutationPending)
	}
	key := layoutOwnerKey(owner)
	ownerID := layoutRolloutOwnerID(owner)
	actor := storageDrainActorForNode(node)
	proof := clusterStorageDrainProof(owner.Status.StorageDrain)
	ownsRoleOnlyDrain := proof != nil && sameStorageDrainActor(proof.Actor, actor) &&
		len(proof.RemovedStorageNodeIDs) == 0
	if owner.Status.StorageDrain != nil && !ownsRoleOnlyDrain {
		return nil, fmt.Errorf("%w: a different durable storage-drain actor owns Garage layout %s/%s", errLayoutMutationPending, key.Namespace, key.Name)
	}
	if ownsRoleOnlyDrain && !coordinator.StorageDrainActorActive(
		key, ownerID, actor.UID, proof.TransactionID, proof.TargetHash,
	) && !coordinator.BeginStorageDrain(
		key, ownerID, actor.UID, proof.TransactionID, proof.TargetHash,
	) {
		return nil, fmt.Errorf("%w: a different storage-drain revision owns Garage layout %s/%s", errLayoutMutationPending, key.Namespace, key.Name)
	}
	if ownsRoleOnlyDrain && !coordinator.ConfirmStorageDrain(
		key, ownerID, actor.UID, proof.TransactionID, proof.TargetHash,
	) {
		return nil, fmt.Errorf("%w: durable GarageNode retirement status lost its in-memory marker", errLayoutMutationPending)
	}
	if coordinator.StorageDrainActive(key) && (!ownsRoleOnlyDrain ||
		!coordinator.StorageDrainActorActive(key, ownerID, actor.UID, proof.TransactionID, proof.TargetHash)) {
		return nil, fmt.Errorf("%w: a different cluster-wide storage drain owns Garage layout %s/%s", errLayoutMutationPending, key.Namespace, key.Name)
	}
	if coordinator.NodeLocalPoolRolloutActive(key) || nodeLocalPoolRolloutConditionActive(owner) {
		return nil, fmt.Errorf("%w: a managed Pod handoff owns Garage layout %s/%s", errLayoutMutationPending, key.Namespace, key.Name)
	}
	if (owner.HasStorageTier() || owner.HasNodeLocalPools()) && storageRolloutMutationBoundaryActive(owner) {
		return nil, fmt.Errorf("%w: the canonical storage owner has an active managed Pod transition", errLayoutMutationPending)
	}
	return acquireLayoutMutationUnconditionally(coordinator, key)
}

func acquireLayoutMutationUnconditionally(
	coordinator *LayoutMutationCoordinator,
	key types.NamespacedName,
) (func(), error) {
	release, ok := coordinator.TryAcquire(key)
	if !ok {
		return nil, fmt.Errorf("%w: another reconciler is changing Garage layout %s/%s", errLayoutMutationPending, key.Namespace, key.Name)
	}
	return release, nil
}

func storageDrainConditionActive(cluster *garagev1beta2.GarageCluster) bool {
	return cluster != nil && cluster.Status.StorageDrain != nil
}

func nodeLocalPoolRolloutConditionActive(cluster *garagev1beta2.GarageCluster) bool {
	if cluster == nil {
		return false
	}
	if cluster.Status.StorageRollout != nil {
		return true
	}
	condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionStorageRolloutReady)
	return condition != nil && condition.Status == metav1.ConditionFalse &&
		condition.Reason == garagev1beta1.ReasonStorageRollingOut
}

// storageRolloutMutationBoundaryActive is broader than the persisted pod
// handoff above. A generation transition is protected from the moment an old
// Converged condition becomes stale, and a Waiting condition keeps ordinary
// layout writers frozen even when health prevents selecting the first pod.
// Initializing is deliberately excluded: first-cluster GarageNode layout joins
// are what allow that condition to converge in the first place.
func storageRolloutMutationBoundaryActive(cluster *garagev1beta2.GarageCluster) bool {
	if cluster == nil {
		return false
	}
	// An exact lost rollout actor can be atomically handed to a durable
	// storage-drain transaction. From that point the drain boundary owns every
	// writer; retaining the broader rollout condition as a second lock would
	// prevent the exact drain actor from fencing and proving destinations.
	if cluster.Status.StorageRollout == nil && cluster.Status.StorageDrain != nil {
		return false
	}
	if cluster.Status.StorageRollout != nil {
		return true
	}
	condition := meta.FindStatusCondition(cluster.Status.Conditions, garagev1beta1.ConditionStorageRolloutReady)
	if condition == nil {
		return false
	}
	if condition.Status == metav1.ConditionTrue {
		return condition.ObservedGeneration != cluster.Generation
	}
	return condition.Reason != garagev1beta1.ReasonStorageRolloutInitializing
}

// storageRolloutBoundaryActive identifies workload-owning clusters whose
// GarageNode and node-local-pool identities share one replacement transaction. Edge
// gateway clusters also use the boundary to observe a referenced storage
// owner's transaction, although their own cluster-level StatefulSet retains
// Kubernetes' ordered RollingUpdate behavior.
func storageRolloutBoundaryActive(cluster *garagev1beta2.GarageCluster) bool {
	return cluster != nil && !cluster.IsManagementHandle()
}

// requireSettledLayoutHistory is called only after the coordinator is held.
// Exclusivity prevents a same-process stage/apply race; the history check
// prevents a second version from starting while Garage still uses an older
// version to synchronize data.
func requireSettledLayoutHistory(ctx context.Context, garageClient *garage.Client) error {
	history, err := garageClient.GetClusterLayoutHistory(ctx)
	if err != nil {
		return fmt.Errorf("verifying Garage layout history before mutation: %w", err)
	}
	return requireSettledLayoutHistoryResponse(history)
}

func requireSettledLayoutHistoryResponse(history *garage.LayoutHistoryResponse) error {
	if history == nil {
		return fmt.Errorf("verifying Garage layout history before mutation returned no response")
	}
	draining := history.GetDrainingVersions()
	if len(draining) == 0 {
		return nil
	}
	// Wait on data movement, not on Garage's bookkeeping. Upstream imposes no
	// settled-history precondition of its own — LayoutHistory::apply_staged_changes
	// only checks version == current+1 and appends; the versions/ack/sync/sync_ack
	// machinery exists precisely so several versions coexist while data migrates.
	// Requiring a fully retired history is therefore stricter than Garage, and it
	// livelocks: a version can stay Draining permanently once every node has
	// synced (see DataMigrationSettled). Blocking there means a single-node
	// `consistent` cluster can never take a second layout change — a plain zone
	// relabel wedges it until the process restarts.
	if history.DataMigrationSettled() {
		return nil
	}
	sort.Slice(draining, func(i, j int) bool { return draining[i].Version < draining[j].Version })
	versions := make([]string, 0, len(draining))
	for i := range draining {
		versions = append(versions, strconv.FormatUint(draining[i].Version, 10))
	}
	// Name the nodes that have not finished, so a drain waiting on a peer that is
	// never coming back is distinguishable from one that is simply still working.
	// The former is what the explicit skip-dead-nodes recovery exists for.
	behind := make([]string, 0, len(history.UpdateTrackers))
	for id, tracker := range history.UpdateTrackers {
		if tracker.Sync < history.CurrentVersion {
			behind = append(behind, fmt.Sprintf("%s(sync=%d)", shortID(id), tracker.Sync))
		}
	}
	sort.Strings(behind)
	detail := "no node has published a sync tracker yet"
	if len(behind) > 0 {
		detail = "waiting on " + strings.Join(behind, ", ")
	}
	return fmt.Errorf(
		"%w: layout version(s) %s are still draining (current version %d); %s",
		errLayoutMutationPending,
		strings.Join(versions, ", "),
		history.CurrentVersion,
		detail,
	)
}

// requireExclusiveStagedRoleChanges prevents an automatic controller action
// from committing another site/controller/CLI user's global Garage staging
// area. Garage exposes Stage and Apply as separate cluster-wide operations;
// there is no per-writer transaction or compare-and-swap token.
func requireExclusiveStagedRoleChanges(
	layout *garage.ClusterLayout,
	intended []garage.NodeRoleChange,
	requireAll bool,
) error {
	if layout == nil {
		return fmt.Errorf("%w: Garage returned no layout while validating staged ownership", errLayoutMutationPending)
	}
	wanted := make(map[string]garage.NodeRoleChange, len(intended))
	for i := range intended {
		wanted[intended[i].ID] = intended[i]
	}
	seen := make(map[string]bool, len(layout.StagedRoleChanges))
	for i := range layout.StagedRoleChanges {
		staged := layout.StagedRoleChanges[i]
		desired, ok := wanted[staged.ID]
		if !ok || !sameStagedRoleChange(staged, desired) {
			return fmt.Errorf(
				"%w: refusing to Apply Garage's global staging area because node %s contains a change not owned by this operation; apply or revert it explicitly first",
				errLayoutMutationPending, shortID(staged.ID),
			)
		}
		seen[staged.ID] = true
	}
	if requireAll {
		for id := range wanted {
			if !seen[id] {
				return fmt.Errorf("%w: intended staged change for node %s is not observable yet", errLayoutMutationPending, shortID(id))
			}
		}
	}
	return nil
}

// requireExclusiveStagedLayoutChanges extends role ownership to Garage's
// global staged parameter slot. A nil intendedParameters means this operation
// owns no parameter mutation and therefore refuses any staged parameters.
func requireExclusiveStagedLayoutChanges(
	layout *garage.ClusterLayout,
	intendedRoles []garage.NodeRoleChange,
	intendedParameters *garage.LayoutParameters,
	requireAll bool,
) error {
	if err := requireExclusiveStagedRoleChanges(layout, intendedRoles, requireAll); err != nil {
		return err
	}
	if layout.StagedParameters != nil &&
		(intendedParameters == nil || !reflect.DeepEqual(layout.StagedParameters, intendedParameters)) {
		return fmt.Errorf("%w: refusing to commit Garage's global staging area because it contains layout parameters not owned by this operation", errLayoutMutationPending)
	}
	if requireAll && intendedParameters != nil && layout.StagedParameters == nil &&
		!reflect.DeepEqual(layout.Parameters, intendedParameters) {
		return fmt.Errorf("%w: intended staged layout parameters are not observable yet", errLayoutMutationPending)
	}
	return nil
}

// stageAndApplyExclusiveLayout is the only automatic Stage→Apply primitive.
// Callers provide the complete set of staged changes they are authorized to
// commit, including compatible leftovers from an interrupted prior attempt.
// The closure stages only changes still missing from the first snapshot.
func stageAndApplyExclusiveLayout(
	ctx context.Context,
	garageClient *garage.Client,
	layout *garage.ClusterLayout,
	intendedRoles []garage.NodeRoleChange,
	intendedParameters *garage.LayoutParameters,
	stage func() error,
) (*garage.ClusterLayout, error) {
	return stageAndApplyExclusiveLayoutWithCheck(
		ctx, garageClient, layout, intendedRoles, intendedParameters, stage, nil,
	)
}

func stageAndApplyExclusiveLayoutWithCheck(
	ctx context.Context,
	garageClient *garage.Client,
	layout *garage.ClusterLayout,
	intendedRoles []garage.NodeRoleChange,
	intendedParameters *garage.LayoutParameters,
	stage func() error,
	beforeApply func(*garage.ClusterLayout) error,
) (*garage.ClusterLayout, error) {
	if err := requireExclusiveStagedLayoutChanges(layout, intendedRoles, intendedParameters, false); err != nil {
		return nil, err
	}
	if err := requireGarageStorageRoleCapacity(layout, intendedRoles); err != nil {
		return nil, err
	}
	if stage != nil {
		if err := stage(); err != nil {
			return nil, err
		}
	}
	staged, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return nil, fmt.Errorf("re-reading Garage's global staging area: %w", err)
	}
	if err := requireExclusiveStagedLayoutChanges(staged, intendedRoles, intendedParameters, true); err != nil {
		return nil, err
	}
	if err := requireGarageStorageRoleCapacity(staged, staged.StagedRoleChanges); err != nil {
		return staged, err
	}
	if len(staged.StagedRoleChanges) == 0 && staged.StagedParameters == nil {
		return staged, nil
	}
	if beforeApply != nil {
		if err := beforeApply(staged); err != nil {
			return staged, err
		}
	}
	if err := garageClient.ApplyStagedLayoutChanges(ctx); err != nil {
		return nil, fmt.Errorf("applying exclusively owned Garage layout changes: %w", err)
	}
	if err := verifyCommittedLayout(ctx, garageClient, intendedRoles, intendedParameters, beforeApply); err != nil {
		return staged, err
	}
	return staged, nil
}

// verifyCommittedLayout confirms that the layout Garage committed contains
// every intended role change, and re-stages and re-applies once if it does
// not.
//
// Garage's staging area is a single last-writer-wins register whose timestamp
// only moves on Apply or Revert; UpdateClusterLayout edits it in place. When
// two independently bootstrapped sites first connect, the site whose last
// Apply is older has its whole staging area replaced by the other site's newer
// (empty) one on the next layout gossip. That can land between the re-read
// above and Garage's Apply, which has no compare-and-swap on staged content:
// Garage then commits a new version without the changes (or Apply finds
// nothing staged and is skipped). In a federation import the other site adopts
// that version and loses its own roles, so the intent held here is the only
// remaining copy and must be re-committed now rather than on a later reconcile.
// After an Apply the local staging timestamp is fresh, so the retry wins.
func verifyCommittedLayout(
	ctx context.Context,
	garageClient *garage.Client,
	intendedRoles []garage.NodeRoleChange,
	intendedParameters *garage.LayoutParameters,
	beforeApply func(*garage.ClusterLayout) error,
) error {
	committed, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("%w: re-reading Garage layout after Apply: %v", errLayoutMutationPending, err)
	}
	missing := uncommittedRoleChanges(committed, intendedRoles)
	if len(missing) == 0 {
		return nil
	}
	logf.FromContext(ctx).Info(
		"Garage committed a layout without changes that were staged just before Apply; re-staging them once",
		"layoutVersion", committed.Version, "missing", len(missing),
	)
	var parameters *garage.LayoutParameters
	if intendedParameters != nil && !reflect.DeepEqual(committed.Parameters, intendedParameters) {
		parameters = intendedParameters
	}
	if err := requireExclusiveStagedLayoutChanges(committed, missing, parameters, false); err != nil {
		return err
	}
	if err := garageClient.UpdateClusterLayoutWithParams(ctx, garage.UpdateClusterLayoutRequest{
		Roles: missing, Parameters: parameters,
	}); err != nil {
		return fmt.Errorf("%w: re-staging layout changes Garage dropped before Apply: %v", errLayoutMutationPending, err)
	}
	restaged, err := garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("%w: re-reading re-staged Garage layout: %v", errLayoutMutationPending, err)
	}
	if err := requireExclusiveStagedLayoutChanges(restaged, missing, parameters, true); err != nil {
		return err
	}
	if beforeApply != nil {
		if err := beforeApply(restaged); err != nil {
			return err
		}
	}
	if err := garageClient.ApplyStagedLayoutChanges(ctx); err != nil {
		return fmt.Errorf("applying re-staged Garage layout changes: %w", err)
	}
	committed, err = garageClient.GetClusterLayout(ctx)
	if err != nil {
		return fmt.Errorf("%w: re-reading Garage layout after re-Apply: %v", errLayoutMutationPending, err)
	}
	if missing := uncommittedRoleChanges(committed, intendedRoles); len(missing) > 0 {
		return fmt.Errorf(
			"%w: Garage committed layout version %d without %d intended role change(s), including node %s, twice",
			errLayoutMutationPending, committed.Version, len(missing), shortID(missing[0].ID),
		)
	}
	return nil
}

// uncommittedRoleChanges returns the intended changes the committed layout
// does not reflect: an assignment whose role is absent or different, or a
// removal whose node still holds a role.
func uncommittedRoleChanges(layout *garage.ClusterLayout, intended []garage.NodeRoleChange) []garage.NodeRoleChange {
	roles := make(map[string]garage.NodeRoleChange, len(layout.Roles))
	for i := range layout.Roles {
		role := &layout.Roles[i]
		roles[role.ID] = garage.NodeRoleChange{ID: role.ID, Zone: role.Zone, Capacity: role.Capacity, Tags: role.Tags}
	}
	var missing []garage.NodeRoleChange
	for i := range intended {
		change := intended[i]
		role, ok := roles[change.ID]
		if change.Remove {
			if ok {
				missing = append(missing, change)
			}
			continue
		}
		if !ok || !sameStagedRoleChange(role, change) {
			missing = append(missing, change)
		}
	}
	return missing
}

const garageMaximumStorageRoles = 256

// requireGarageStorageRoleCapacity mirrors Garage's CompactNodeType=u8 hard
// limit before any automatic Stage or Apply. This is only the upstream hard
// boundary: it does not reserve role 256 for node-local work. Node-local
// activation applies its narrower admission policy separately, and removals
// remain possible at the hard limit.
func requireGarageStorageRoleCapacity(
	layout *garage.ClusterLayout,
	changes []garage.NodeRoleChange,
) error {
	if layout == nil {
		return fmt.Errorf("%w: Garage layout is unavailable while checking the storage-role limit", errLayoutMutationPending)
	}
	storageRoles := projectedGarageStorageRoleIDs(layout, changes)
	if len(storageRoles) > garageMaximumStorageRoles {
		return fmt.Errorf(
			"%w: projected Garage layout has %d positive-capacity roles, above Garage's hard maximum of %d; drain an existing role before activating another identity",
			errLayoutMutationPending, len(storageRoles), garageMaximumStorageRoles,
		)
	}
	return nil
}

func projectedGarageStorageRoleIDs(
	layout *garage.ClusterLayout,
	changes []garage.NodeRoleChange,
) map[string]struct{} {
	storageRoles := make(map[string]struct{}, len(layout.Roles)+len(changes))
	for i := range layout.Roles {
		role := &layout.Roles[i]
		if role.Capacity != nil {
			storageRoles[canonicalGarageNodeID(role.ID)] = struct{}{}
		}
	}
	for i := range changes {
		change := &changes[i]
		id := canonicalGarageNodeID(change.ID)
		if id == "" {
			continue
		}
		if change.Remove || change.Capacity == nil {
			delete(storageRoles, id)
			continue
		}
		storageRoles[id] = struct{}{}
	}
	return storageRoles
}

func sameStagedRoleChange(left, right garage.NodeRoleChange) bool {
	if left.ID != right.ID || left.Remove != right.Remove {
		return false
	}
	if left.Remove {
		return true
	}
	if left.Zone != right.Zone || !tagSetEqual(left.Tags, right.Tags) ||
		(left.Capacity == nil) != (right.Capacity == nil) {
		return false
	}
	return left.Capacity == nil || *left.Capacity == *right.Capacity
}

func runLayoutMutation(
	ctx context.Context,
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
	mutate func() error,
) error {
	release, err := acquireLayoutMutation(coordinator, cluster)
	if err != nil {
		return err
	}
	defer release()
	if err := requireSettledLayoutHistory(ctx, garageClient); err != nil {
		return err
	}
	return mutate()
}

// runResolvedLayoutMutation resolves clusterRef chains before acquiring the
// layout lock. It is the cluster-controller entry point for edge gateways and
// management handles; direct callers that already hold the canonical owner can
// continue to use runLayoutMutation.
func runResolvedLayoutMutation(
	ctx context.Context,
	reader client.Reader,
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
	mutate func() error,
) error {
	owner, err := resolveGarageLayoutOwner(ctx, reader, cluster)
	if err != nil {
		return fmt.Errorf("%w: resolving canonical Garage layout owner: %v", errLayoutMutationPending, err)
	}
	if owner != cluster && (storageDrainConditionActive(cluster) || storageRolloutMutationBoundaryActive(cluster)) {
		return fmt.Errorf("%w: the referring GarageCluster has an active storage drain or managed pod rollout", errLayoutMutationPending)
	}
	return runLayoutMutation(ctx, coordinator, owner, garageClient, mutate)
}

// runLayoutAdministrativeMutation serializes operations that modify global
// staging/history state but must be usable precisely when history is not
// settled (Revert and exact capacity-less gateway retirement). It still honors
// active drain/rollout boundaries and every other writer; it deliberately
// omits requireSettledLayoutHistory.
func runLayoutAdministrativeMutation(
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
	mutate func() error,
) error {
	release, err := acquireLayoutMutation(coordinator, cluster)
	if err != nil {
		return err
	}
	defer release()
	return mutate()
}

// runResolvedExplicitDeadNodeRecoveryMutation is reserved for the
// administrator-requested skip-dead-nodes annotation. It may run while a
// durable storage drain is waiting for a dead peer to ACK, but never during a
// managed-Pod handoff or storage rollout. The process-wide mutex still prevents
// it from racing Stage/Apply.
func runResolvedExplicitDeadNodeRecoveryMutation(
	ctx context.Context,
	reader client.Reader,
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
	mutate func() error,
) error {
	owner, err := resolveGarageLayoutOwner(ctx, reader, cluster)
	if err != nil {
		return fmt.Errorf("%w: resolving canonical Garage layout owner: %v", errLayoutMutationPending, err)
	}
	key := layoutOwnerKey(owner)
	if coordinator.NodeLocalPoolRolloutActive(key) || storageRolloutMutationBoundaryActive(owner) ||
		(owner != cluster && storageRolloutMutationBoundaryActive(cluster)) {
		return fmt.Errorf("%w: explicit dead-node recovery is waiting for the active managed-Pod rollout", errLayoutMutationPending)
	}
	release, err := acquireLayoutMutationUnconditionally(coordinator, key)
	if err != nil {
		return err
	}
	defer release()
	return mutate()
}

func runResolvedLayoutAdministrativeMutation(
	ctx context.Context,
	reader client.Reader,
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
	mutate func() error,
) error {
	owner, err := resolveGarageLayoutOwner(ctx, reader, cluster)
	if err != nil {
		return fmt.Errorf("%w: resolving canonical Garage layout owner: %v", errLayoutMutationPending, err)
	}
	if owner != cluster && (storageDrainConditionActive(cluster) || storageRolloutMutationBoundaryActive(cluster)) {
		return fmt.Errorf("%w: the referring GarageCluster has an active storage drain or managed pod rollout", errLayoutMutationPending)
	}
	return runLayoutAdministrativeMutation(coordinator, owner, mutate)
}

// runResolvedCapacitylessRoleRetirementMutation is the deletion-only edge
// gateway path. A referring gateway's stale workload-generation condition does
// not protect object blocks and cannot be allowed to deadlock removal of its
// exact capacity-less role after deletionTimestamp is set. The canonical
// storage owner still goes through runLayoutAdministrativeMutation, so its
// active storage drain/rollout marker and every competing global writer remain
// hard exclusions.
func runResolvedCapacitylessRoleRetirementMutation(
	ctx context.Context,
	reader client.Reader,
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
	mutate func() error,
) error {
	if cluster == nil || cluster.DeletionTimestamp.IsZero() || !cluster.HasGatewayTier() ||
		cluster.HasStorageTier() || cluster.HasNodeLocalPools() {
		return fmt.Errorf("%w: capacity-less role retirement is restricted to a deleting gateway-only GarageCluster", errLayoutMutationPending)
	}
	owner, err := resolveGarageLayoutOwner(ctx, reader, cluster)
	if err != nil {
		return fmt.Errorf("%w: resolving canonical Garage layout owner: %v", errLayoutMutationPending, err)
	}
	release, err := acquireCapacitylessRoleRetirementMutation(coordinator, owner, cluster)
	if err != nil {
		return err
	}
	defer release()
	return mutate()
}

// runCapacitylessGarageNodeRoleRetirementMutation deliberately omits the
// pre-mutation settled-history gate. Removing this exact live gateway role can
// be the operation needed for an older metadata version to settle. finalize
// persists the exact actor and target before Apply and then waits for normal
// ACK/sync convergence before allowing the workload to disappear.
func runCapacitylessGarageNodeRoleRetirementMutation(
	coordinator *LayoutMutationCoordinator,
	owner *garagev1beta2.GarageCluster,
	node *garagev1beta1.GarageNode,
	mutate func() error,
) error {
	release, err := acquireCapacitylessGarageNodeRetirementMutation(coordinator, owner, node)
	if err != nil {
		return err
	}
	defer release()
	return mutate()
}

// runLayoutMutationIgnoringNodeLocalPoolRollout is reserved for the single
// persisted GarageNode actor whose pod is being replaced. It still serializes
// against every other writer and rechecks upstream layout history; it bypasses
// only the rollout exclusion that would otherwise prevent that identity from
// reconnecting or completing an add-before-remove identity recovery.
func runLayoutMutationIgnoringNodeLocalPoolRollout(
	ctx context.Context,
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
	mutate func() error,
) error {
	release, err := acquireLayoutMutationIgnoringNodeLocalPoolRollout(coordinator, cluster)
	if err != nil {
		return err
	}
	defer release()
	if err := requireSettledLayoutHistory(ctx, garageClient); err != nil {
		return err
	}
	return mutate()
}

// runLayoutMutationDuringStorageRolloutPrepare permits only the GarageNode
// convergence work that precedes selection of an exact OnDelete Pod actor. It
// retains the canonical layout mutex and settled-history proof and therefore
// cannot overlap another stage/apply operation.
func runLayoutMutationDuringStorageRolloutPrepare(
	ctx context.Context,
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
	garageClient *garage.Client,
	mutate func() error,
) error {
	release, err := acquireLayoutMutationDuringStorageRolloutPrepare(coordinator, cluster)
	if err != nil {
		return err
	}
	defer release()
	if err := requireSettledLayoutHistory(ctx, garageClient); err != nil {
		return err
	}
	return mutate()
}

// runLayoutMutationIgnoringStorageDrain is reserved for the exact actor and
// target revision persisted in status.storageDrain. Callers must additionally
// constrain mutate to the recorded role removals (plus allowMissingData=false
// acknowledgement); this function is not a general layout-writer bypass.
func runLayoutMutationIgnoringStorageDrain(
	ctx context.Context,
	coordinator *LayoutMutationCoordinator,
	cluster *garagev1beta2.GarageCluster,
	actor storageDrainActor,
	garageClient *garage.Client,
	mutate func() error,
) error {
	release, err := acquireLayoutMutationIgnoringStorageDrain(coordinator, cluster, actor)
	if err != nil {
		return err
	}
	defer release()
	if err := requireSettledLayoutHistory(ctx, garageClient); err != nil {
		return err
	}
	return mutate()
}
