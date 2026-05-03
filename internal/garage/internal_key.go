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

// operator-internal s3 credential lifecycle: one Secret per GarageCluster,
// stored in the cluster's namespace so the ownerRef is valid and the cache
// covers it when namespace-scoped watching is in use.
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
package garage

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// internal key Secret data keys
const (
	internalKeyAccessKeyIDField     = "accessKeyId"
	internalKeySecretAccessKeyField = "secretAccessKey"
	internalKeyGarageNameField      = "garageKeyName"

	// Label so users can identify operator-internal Secrets at a glance.
	internalKeyOwnerLabel      = "garage.rajsingh.info/owner"
	internalKeyOwnerLabelValue = "operator-internal"
)

// ClusterRef is the minimal handle on a GarageCluster the key manager needs:
// stable identity for naming, namespace+name for the owner ref, and a
// TypeMeta-equivalent so we can construct OwnerReferences without depending on
// the api/v1beta1 package (avoids an import cycle).
type ClusterRef struct {
	Name       string
	Namespace  string
	UID        types.UID
	APIVersion string
	Kind       string
}

// InternalCredentials are S3 access credentials for the operator's internal
// key on a given cluster.
type InternalCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	GarageKeyName   string
}

// InternalKeyManager bootstraps and recalls a per-cluster operator-managed
// access key. Garage exposes lifecycle config (and other features) only via
// the S3 API, which requires SigV4 with a key that has owner permission on
// the target bucket. This manager keeps one stable key per cluster so we
// don't churn keys per reconcile.
type InternalKeyManager struct {
	K8s client.Client
}

// NewInternalKeyManager constructs an InternalKeyManager.
func NewInternalKeyManager(k8s client.Client) *InternalKeyManager {
	return &InternalKeyManager{K8s: k8s}
}

// SecretName returns the Secret name used to persist credentials for the
// given cluster.
func (m *InternalKeyManager) SecretName(cluster ClusterRef) string {
	return fmt.Sprintf("garage-operator-internal-%s", cluster.UID)
}

// EnsureKey returns credentials for the operator-internal key on the given
// cluster, creating the Garage key (and the persisting Secret) on first use.
//
// On miss, this calls admin CreateKey. The Secret is stored in the cluster's
// namespace so the ownerRef is valid and the object is GC'd when the cluster
// is deleted.
func (m *InternalKeyManager) EnsureKey(ctx context.Context, cluster ClusterRef, garageClient *Client) (*InternalCredentials, error) {
	secretName := m.SecretName(cluster)
	key := types.NamespacedName{Namespace: cluster.Namespace, Name: secretName}

	var sec corev1.Secret
	err := m.K8s.Get(ctx, key, &sec)
	switch {
	case err == nil:
		creds, ok := credsFromSecret(&sec)
		if ok {
			return creds, nil
		}
		// Secret exists but is missing required fields, e.g. after a manual
		// edit. Drop any garage key it still pointed at, then delete the
		// Secret so we can recreate cleanly below.
		log := ctrl.LoggerFrom(ctx)
		log.Info("internal key Secret malformed, recreating", "secret", key)
		if staleID := string(sec.Data[internalKeyAccessKeyIDField]); staleID != "" {
			if err := garageClient.DeleteKey(ctx, staleID); err != nil && !IsNotFound(err) {
				return nil, fmt.Errorf("delete stale operator-internal garage key: %w", err)
			}
		}
		if err := m.K8s.Delete(ctx, &sec); err != nil && !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("delete malformed internal key secret: %w", err)
		}
	case apierrors.IsNotFound(err):
	default:
		return nil, fmt.Errorf("get internal key secret: %w", err)
	}

	creds, err := m.createGarageKey(ctx, cluster, garageClient)
	if err != nil {
		return nil, err
	}
	if err := m.persistSecret(ctx, cluster, secretName, creds); err != nil {
		// concurrent reconcile beat us to persistSecret. honour the winner's
		// credentials so k8s converges on one secret, and best-effort drop
		// our just-created garage key so we don't leave it orphaned.
		if apierrors.IsAlreadyExists(err) {
			var existing corev1.Secret
			if getErr := m.K8s.Get(ctx, key, &existing); getErr == nil {
				if winning, ok := credsFromSecret(&existing); ok {
					if delErr := garageClient.DeleteKey(ctx, creds.AccessKeyID); delErr != nil && !IsNotFound(delErr) {
						// next reconcile has no signal to retry; log and move on.
						ctrl.LoggerFrom(ctx).Error(delErr, "failed to delete losing operator-internal garage key", "accessKeyId", creds.AccessKeyID)
					}
					return winning, nil
				}
			}
		}
		return nil, fmt.Errorf("persist internal key secret: %w", err)
	}
	return creds, nil
}

// createGarageKey creates a new access key in Garage for operator-internal
// use. The returned secretAccessKey is only available at creation time, so
// the caller must persist it immediately.
func (m *InternalKeyManager) createGarageKey(ctx context.Context, cluster ClusterRef, garageClient *Client) (*InternalCredentials, error) {
	// Human-readable prefix aids debugging; uniqueness comes from the cluster UID.
	name := fmt.Sprintf("operator-internal/%s", cluster.UID)
	key, err := garageClient.CreateKey(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("create garage key: %w", err)
	}
	if key.SecretAccessKey == "" {
		return nil, fmt.Errorf("garage CreateKey returned empty secret access key")
	}
	return &InternalCredentials{
		AccessKeyID:     key.AccessKeyID,
		SecretAccessKey: key.SecretAccessKey,
		GarageKeyName:   key.Name,
	}, nil
}

// persistSecret stores credentials in a Secret owner-ref'd to the cluster.
func (m *InternalKeyManager) persistSecret(ctx context.Context, cluster ClusterRef, secretName string, creds *InternalCredentials) error {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels: map[string]string{
				internalKeyOwnerLabel: internalKeyOwnerLabelValue,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: cluster.APIVersion,
					Kind:       cluster.Kind,
					Name:       cluster.Name,
					UID:        cluster.UID,
				},
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			internalKeyAccessKeyIDField:     []byte(creds.AccessKeyID),
			internalKeySecretAccessKeyField: []byte(creds.SecretAccessKey),
			internalKeyGarageNameField:      []byte(creds.GarageKeyName),
		},
	}
	return m.K8s.Create(ctx, sec)
}

// DeleteSecret removes the operator-internal Secret for the given cluster.
func (m *InternalKeyManager) DeleteSecret(ctx context.Context, cluster ClusterRef) error {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.SecretName(cluster),
			Namespace: cluster.Namespace,
		},
	}
	if err := m.K8s.Delete(ctx, sec); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete internal key secret: %w", err)
	}
	return nil
}

// DeleteKey deletes the operator-internal credential pair. The Garage access
// key is best-effort; the Secret is always removed when present.
//
// adminClientFn is called only after a Secret is found (so callers don't pay
// for admin-token lookups on clusters that never had an internal key). Return
// nil from the closure to skip the Garage-side delete.
func (m *InternalKeyManager) DeleteKey(ctx context.Context, cluster ClusterRef, adminClientFn func() *Client) error {
	log := ctrl.LoggerFrom(ctx)

	key := types.NamespacedName{Namespace: cluster.Namespace, Name: m.SecretName(cluster)}
	var sec corev1.Secret
	switch err := m.K8s.Get(ctx, key, &sec); {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("get internal key secret: %w", err)
	}

	creds, credsOK := credsFromSecret(&sec)
	switch {
	case !credsOK:
		log.Info("internal key Secret malformed, skipping garage DeleteKey", "secret", key)
	default:
		if c := adminClientFn(); c == nil {
			log.Info("admin client unavailable, skipping garage DeleteKey", "secret", key)
		} else if err := c.DeleteKey(ctx, creds.AccessKeyID); err != nil && !IsNotFound(err) {
			// stale key beats stuck finalizer.
			log.Error(err, "failed to delete operator-internal garage key", "accessKeyId", creds.AccessKeyID)
		}
	}

	return m.DeleteSecret(ctx, cluster)
}

func credsFromSecret(sec *corev1.Secret) (*InternalCredentials, bool) {
	id := string(sec.Data[internalKeyAccessKeyIDField])
	secret := string(sec.Data[internalKeySecretAccessKeyField])
	if id == "" || secret == "" {
		return nil, false
	}
	return &InternalCredentials{
		AccessKeyID:     id,
		SecretAccessKey: secret,
		GarageKeyName:   string(sec.Data[internalKeyGarageNameField]),
	}, true
}
