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

package cosi

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	cosiv1alpha2 "sigs.k8s.io/container-object-storage-interface/client/apis/objectstorage/v1alpha2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
	garagecontroller "github.com/rajsinghtech/garage-operator/internal/controller"
	"github.com/rajsinghtech/garage-operator/internal/garage"
)

type foreignSecretCreateRaceClient struct {
	client.Client
	target  types.NamespacedName
	foreign *corev1.Secret
	wonRace bool
}

func (c *foreignSecretCreateRaceClient) Create(ctx context.Context, object client.Object, opts ...client.CreateOption) error {
	secret, ok := object.(*corev1.Secret)
	if !ok || c.wonRace || client.ObjectKeyFromObject(secret) != c.target {
		return c.Client.Create(ctx, object, opts...)
	}
	c.wonRace = true
	if err := c.Client.Create(ctx, c.foreign.DeepCopy()); err != nil {
		return err
	}
	return apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, secret.Name)
}

func TestCOSIProtocolValidationFailsClosed(t *testing.T) {
	require.Error(t, validateS3BucketProtocols(nil))
	require.NoError(t, validateS3BucketProtocols([]cosiv1alpha2.ObjectProtocol{cosiv1alpha2.ObjectProtocolS3}))
	require.Error(t, validateS3BucketProtocols([]cosiv1alpha2.ObjectProtocol{
		cosiv1alpha2.ObjectProtocolS3, cosiv1alpha2.ObjectProtocolS3,
	}))
	require.Error(t, validateS3BucketProtocols([]cosiv1alpha2.ObjectProtocol{cosiv1alpha2.ObjectProtocolAzure}))
	require.Error(t, validateS3BucketProtocols([]cosiv1alpha2.ObjectProtocol{
		cosiv1alpha2.ObjectProtocolS3, cosiv1alpha2.ObjectProtocolGcs,
	}))
	require.NoError(t, validateS3AccessProtocol(cosiv1alpha2.ObjectProtocolS3))
	require.Error(t, validateS3AccessProtocol(cosiv1alpha2.ObjectProtocolAzure))
}

func TestDuplicateAccessSecretNamesAreRejected(t *testing.T) {
	claims := []cosiv1alpha2.BucketClaimAccess{
		{BucketClaimName: "one", AccessSecretName: "shared"},
		{BucketClaimName: "two", AccessSecretName: "shared"},
	}
	require.ErrorContains(t, validateUniqueAccessSecretNames(claims), "same accessSecretName")
}

func TestDynamicBucketClaimRefRequiresUID(t *testing.T) {
	ref := cosiv1alpha2.BucketClaimReference{Name: "claim", Namespace: "apps"}
	require.Error(t, validateDynamicBucketClaimRef(ref))
	ref.UID = types.UID("11111111-1111-1111-1111-111111111111")
	require.NoError(t, validateDynamicBucketClaimRef(ref))
}

func TestResolveBucketsRejectsEmptyClaimReferenceUID(t *testing.T) {
	claim := &cosiv1alpha2.BucketClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "claim", Namespace: "tenant", UID: "claim-uid"},
		Status:     cosiv1alpha2.BucketClaimStatus{BoundBucketName: "bucket"},
	}
	bucket := &cosiv1alpha2.Bucket{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket"},
		Spec: cosiv1alpha2.BucketSpec{
			DriverName:     cosiTestDriver,
			BucketClaimRef: cosiv1alpha2.BucketClaimReference{Name: claim.Name, Namespace: claim.Namespace},
		},
		Status: cosiv1alpha2.BucketStatus{BucketID: "bucket-id"},
	}
	access := &cosiv1alpha2.BucketAccess{
		ObjectMeta: metav1.ObjectMeta{Name: "access", Namespace: claim.Namespace, UID: "access-uid"},
		Spec:       cosiv1alpha2.BucketAccessSpec{BucketClaims: []cosiv1alpha2.BucketClaimAccess{{BucketClaimName: claim.Name}}},
	}
	kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(claim, bucket, access).Build()
	reconciler := &BucketAccessReconciler{Client: kubeClient, DriverName: cosiTestDriver}

	_, _, err := reconciler.resolveBuckets(t.Context(), access)
	require.ErrorContains(t, err, "does not belong to BucketClaim")
}

func TestUnknownClassParametersCauseNoRemoteMutation(t *testing.T) {
	t.Run("BucketClass", func(t *testing.T) {
		bucket := &cosiv1alpha2.Bucket{
			ObjectMeta: metav1.ObjectMeta{Name: "bucket"},
			Spec: cosiv1alpha2.BucketSpec{
				DriverName: cosiTestDriver,
				Parameters: map[string]string{paramClusterRef: "cluster", "clusterNamspace": "typo"},
				Protocols:  []cosiv1alpha2.ObjectProtocol{cosiv1alpha2.ObjectProtocolS3},
				BucketClaimRef: cosiv1alpha2.BucketClaimReference{
					Name: "claim", Namespace: "tenant", UID: "claim-uid",
				},
			},
		}
		kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(bucket).Build()
		factoryCalled := false
		provisioner := NewProvisionerWithFactory(kubeClient, testGarageSystem,
			func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
				factoryCalled = true
				return newMockGarageClient(), nil
			})
		reconciler := &BucketReconciler{Client: kubeClient, DriverName: cosiTestDriver, Namespace: testGarageSystem, Provisioner: provisioner}

		_, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(bucket)})
		require.ErrorContains(t, err, "unsupported BucketClass parameters: clusterNamspace")
		require.False(t, factoryCalled)
	})

	t.Run("BucketAccessClass", func(t *testing.T) {
		access := &cosiv1alpha2.BucketAccess{
			ObjectMeta: metav1.ObjectMeta{Name: "access", Namespace: "tenant", UID: "access-uid"},
			Spec:       cosiv1alpha2.BucketAccessSpec{Protocol: cosiv1alpha2.ObjectProtocolS3},
			Status: cosiv1alpha2.BucketAccessStatus{
				DriverName: cosiTestDriver,
				Parameters: map[string]string{paramClusterRef: "cluster", "clusterNamspace": "typo"},
			},
		}
		kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(access).Build()
		factoryCalled := false
		provisioner := NewProvisionerWithFactory(kubeClient, testGarageSystem,
			func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
				factoryCalled = true
				return newMockGarageClient(), nil
			})
		reconciler := &BucketAccessReconciler{Client: kubeClient, DriverName: cosiTestDriver, Namespace: testGarageSystem, Provisioner: provisioner}

		_, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(access)})
		require.ErrorContains(t, err, "unsupported BucketAccessClass parameters: clusterNamspace")
		require.False(t, factoryCalled)
	})
}

func TestNamespaceScopedBucketReconcilerIgnoresOutOfScopeClaims(t *testing.T) {
	bucket := &cosiv1alpha2.Bucket{
		ObjectMeta: metav1.ObjectMeta{Name: "out-of-scope"},
		Spec: cosiv1alpha2.BucketSpec{
			DriverName: cosiTestDriver,
			BucketClaimRef: cosiv1alpha2.BucketClaimReference{
				Name: "claim", Namespace: "foreign", UID: "claim-uid",
			},
		},
	}
	kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(bucket).Build()
	factoryCalled := false
	provisioner := NewProvisionerWithFactory(kubeClient, testGarageSystem,
		func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
			factoryCalled = true
			return newMockGarageClient(), nil
		})
	reconciler := &BucketReconciler{
		Client: kubeClient, DriverName: cosiTestDriver, Namespace: testGarageSystem,
		Provisioner: provisioner, WatchNamespaces: []string{"tenant"},
	}

	_, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(bucket)})
	require.NoError(t, err)
	require.False(t, factoryCalled)
	fresh := &cosiv1alpha2.Bucket{}
	require.NoError(t, kubeClient.Get(t.Context(), client.ObjectKeyFromObject(bucket), fresh))
	require.NotContains(t, fresh.Finalizers, GarageProtectionFinalizer)
	require.Empty(t, fresh.Status.BucketID)
	require.Nil(t, fresh.Status.Error)
}

func TestNamespaceScopedBucketReconcilerCleansPreviouslyOwnedOutOfScopeBuckets(t *testing.T) {
	for _, deletionPolicy := range []cosiv1alpha2.BucketDeletionPolicy{
		cosiv1alpha2.BucketDeletionPolicyDelete,
		cosiv1alpha2.BucketDeletionPolicyRetain,
	} {
		t.Run(string(deletionPolicy), func(t *testing.T) {
			now := metav1.Now()
			bucket := &cosiv1alpha2.Bucket{
				ObjectMeta: metav1.ObjectMeta{
					Name: "previously-managed-" + string(deletionPolicy), DeletionTimestamp: &now,
					Finalizers: []string{GarageProtectionFinalizer},
				},
				Spec: cosiv1alpha2.BucketSpec{
					DriverName: cosiTestDriver, DeletionPolicy: deletionPolicy,
					BucketClaimRef: cosiv1alpha2.BucketClaimReference{Name: "claim", Namespace: "old-scope", UID: "claim-uid"},
					Parameters:     map[string]string{paramClusterRef: testMyCluster, paramClusterNamespace: testGarageSystem},
				},
				Status: cosiv1alpha2.BucketStatus{BucketID: testBucketID},
			}
			shadow := createShadowBucket(testBucketID, bucket.Name)
			shadow.UID = types.UID(bucket.Name + "-shadow-uid")
			shadow.Finalizers = []string{garagev1beta1.GarageBucketFinalizer}
			cluster := createReadyCluster()
			kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(bucket, shadow, cluster).Build()
			mockClient := newMockGarageClient()
			mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
			provisioner := NewProvisionerWithFactory(kubeClient, testGarageSystem,
				func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
					return mockClient, nil
				})
			reconciler := &BucketReconciler{
				Client: kubeClient, DriverName: cosiTestDriver, Namespace: testGarageSystem,
				Provisioner: provisioner, WatchNamespaces: []string{"new-scope"},
			}

			_, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(bucket)})
			require.NoError(t, err)
			if deletionPolicy == cosiv1alpha2.BucketDeletionPolicyDelete {
				require.Equal(t, []string{testBucketID}, mockClient.deleteBucketCalls)
				fresh := &cosiv1alpha2.Bucket{}
				err = kubeClient.Get(t.Context(), client.ObjectKeyFromObject(bucket), fresh)
				if err == nil {
					require.NotContains(t, fresh.Finalizers, GarageProtectionFinalizer)
				} else {
					require.True(t, apierrors.IsNotFound(err))
				}
				return
			}

			require.Empty(t, mockClient.deleteBucketCalls, "Retain must not delete the Garage bucket")
			freshShadow := &garagev1beta1.GarageBucket{}
			require.NoError(t, kubeClient.Get(t.Context(), client.ObjectKeyFromObject(shadow), freshShadow))
			require.False(t, freshShadow.DeletionTimestamp.IsZero(), "Retain cleanup must start forgetting the owned shadow")
		})
	}
}

func TestBucketReconcilerNonEmptyDeletionSurfacesStatusAndBacksOff(t *testing.T) {
	now := metav1.Now()
	bucket := &cosiv1alpha2.Bucket{
		ObjectMeta: metav1.ObjectMeta{
			Name: "non-empty-bucket", Finalizers: []string{cosiv1alpha2.ProtectionFinalizer, GarageProtectionFinalizer},
			DeletionTimestamp: &now,
			Annotations:       map[string]string{garagecontroller.FinalizationRetryAnnotation: "1"},
		},
		Spec: cosiv1alpha2.BucketSpec{
			DriverName:     cosiTestDriver,
			DeletionPolicy: cosiv1alpha2.BucketDeletionPolicyDelete,
			Parameters: map[string]string{
				paramClusterRef:       testMyCluster,
				paramClusterNamespace: testGarageSystem,
			},
		},
		Status: cosiv1alpha2.BucketStatus{BucketID: testBucketID},
	}
	cluster := createReadyCluster()
	kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(bucket, cluster).Build()
	mockClient := newMockGarageClient()
	mockClient.deleteBucketErr = &garage.APIError{StatusCode: 409, Message: "BucketNotEmpty"}
	provisioner := NewProvisionerWithFactory(kubeClient, testGarageSystem,
		func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
			return mockClient, nil
		})
	reconciler := &BucketReconciler{
		Client: kubeClient, Scheme: kubeClient.Scheme(), DriverName: cosiTestDriver,
		Namespace: testGarageSystem, Provisioner: provisioner,
	}

	result, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(bucket)})
	require.NoError(t, err)
	require.Equal(t, garagecontroller.FinalizationRetryDelay(2), result.RequeueAfter)
	require.Equal(t, []string{testBucketID}, mockClient.deleteBucketCalls)

	fresh := &cosiv1alpha2.Bucket{}
	require.NoError(t, kubeClient.Get(t.Context(), client.ObjectKeyFromObject(bucket), fresh))
	require.Equal(t, "2", fresh.Annotations[garagecontroller.FinalizationRetryAnnotation])
	require.Contains(t, fresh.Finalizers, GarageProtectionFinalizer)
	require.NotNil(t, fresh.Status.ReadyToUse)
	require.False(t, *fresh.Status.ReadyToUse)
	require.NotNil(t, fresh.Status.Error)
	require.NotNil(t, fresh.Status.Error.Message)
	require.Contains(t, *fresh.Status.Error.Message, "remove all objects")
	require.Contains(t, *fresh.Status.Error.Message, "never empties")
}

func TestBucketAccessDeletionRetainsAccessUntilBucketCleanupFinishes(t *testing.T) {
	const (
		accessName = "cleanup-access"
		bucketName = "cleanup-bucket"
		accountID  = "GKcleanup"
	)
	now := metav1.Now()
	bucket := &cosiv1alpha2.Bucket{
		ObjectMeta: metav1.ObjectMeta{
			Name:       bucketName,
			Finalizers: []string{GarageProtectionFinalizer},
			Annotations: map[string]string{
				// COSI intentionally uses an empty annotation value. Presence,
				// rather than a non-empty value, is the deletion signal.
				cosiv1alpha2.BucketClaimBeingDeletedAnnotation: "",
			},
		},
		Spec: cosiv1alpha2.BucketSpec{
			DriverName:     cosiTestDriver,
			DeletionPolicy: cosiv1alpha2.BucketDeletionPolicyDelete,
			BucketClaimRef: cosiv1alpha2.BucketClaimReference{Name: "claim", Namespace: "tenant"},
		},
		Status: cosiv1alpha2.BucketStatus{BucketID: testBucketID},
	}
	access := &cosiv1alpha2.BucketAccess{
		ObjectMeta: metav1.ObjectMeta{
			Name: accessName, Namespace: "tenant", UID: "cleanup-access-uid",
			Finalizers:        []string{GarageProtectionFinalizer},
			DeletionTimestamp: &now,
			Annotations:       map[string]string{garagecontroller.FinalizationRetryAnnotation: "1"},
		},
		Status: cosiv1alpha2.BucketAccessStatus{
			ReadyToUse: ptr.To(true), DriverName: cosiTestDriver, AccountID: accountID,
			AccessedBuckets: []cosiv1alpha2.AccessedBucket{{
				BucketName: bucketName, BucketID: testBucketID, BucketClaimName: "claim",
			}},
			Parameters: map[string]string{
				paramClusterRef:       testMyCluster,
				paramClusterNamespace: testGarageSystem,
			},
		},
	}
	cluster := createReadyCluster()
	kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(bucket, access, cluster).Build()
	mockClient := newMockGarageClient()
	mockClient.keys[accountID] = &garage.Key{AccessKeyID: accountID}
	provisioner := NewProvisionerWithFactory(kubeClient, testGarageSystem,
		func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
			return mockClient, nil
		})
	reconciler := &BucketAccessReconciler{
		Client: kubeClient, Scheme: kubeClient.Scheme(), DriverName: cosiTestDriver,
		Namespace: testGarageSystem, Provisioner: provisioner,
	}

	result, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(access)})
	require.NoError(t, err)
	require.Equal(t, garagecontroller.FinalizationRetryDelay(2), result.RequeueAfter)
	require.Empty(t, mockClient.deleteKeyCalls)
	require.Empty(t, mockClient.denyBucketKeyCalls)

	fresh := &cosiv1alpha2.BucketAccess{}
	require.NoError(t, kubeClient.Get(t.Context(), client.ObjectKeyFromObject(access), fresh))
	require.Contains(t, fresh.Finalizers, GarageProtectionFinalizer)
	require.Equal(t, "2", fresh.Annotations[garagecontroller.FinalizationRetryAnnotation])
	require.NotNil(t, fresh.Status.ReadyToUse)
	require.False(t, *fresh.Status.ReadyToUse)
	require.NotNil(t, fresh.Status.Error)
	require.NotNil(t, fresh.Status.Error.Message)
	require.Contains(t, *fresh.Status.Error.Message, "remove all objects")
	require.Contains(t, *fresh.Status.Error.Message, bucketName)
}

func TestBucketAccessDeletionRevokesAfterBucketCleanupFinalizerIsGone(t *testing.T) {
	const (
		accessName = "released-access"
		bucketName = "released-bucket"
		accountID  = "GKreleased"
	)
	now := metav1.Now()
	bucket := &cosiv1alpha2.Bucket{
		ObjectMeta: metav1.ObjectMeta{Name: bucketName, Finalizers: []string{"example.test/finished"}, DeletionTimestamp: &now},
		Spec: cosiv1alpha2.BucketSpec{
			DriverName:     cosiTestDriver,
			DeletionPolicy: cosiv1alpha2.BucketDeletionPolicyDelete,
			BucketClaimRef: cosiv1alpha2.BucketClaimReference{Name: "claim", Namespace: "tenant"},
		},
		Status: cosiv1alpha2.BucketStatus{BucketID: testBucketID},
	}
	access := &cosiv1alpha2.BucketAccess{
		ObjectMeta: metav1.ObjectMeta{
			Name: accessName, Namespace: "tenant", UID: "released-access-uid",
			Finalizers: []string{GarageProtectionFinalizer}, DeletionTimestamp: &now,
		},
		Status: cosiv1alpha2.BucketAccessStatus{
			ReadyToUse: ptr.To(false), DriverName: cosiTestDriver, AccountID: accountID,
			AccessedBuckets: []cosiv1alpha2.AccessedBucket{{
				BucketName: bucketName, BucketID: testBucketID, BucketClaimName: "claim",
			}},
			Parameters: map[string]string{
				paramClusterRef:       testMyCluster,
				paramClusterNamespace: testGarageSystem,
			},
		},
	}
	cluster := createReadyCluster()
	kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(bucket, access, cluster).Build()
	mockClient := newMockGarageClient()
	mockClient.keys[accountID] = &garage.Key{AccessKeyID: accountID}
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	provisioner := NewProvisionerWithFactory(kubeClient, testGarageSystem,
		func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
			return mockClient, nil
		})
	reconciler := &BucketAccessReconciler{
		Client: kubeClient, Scheme: kubeClient.Scheme(), DriverName: cosiTestDriver,
		Namespace: testGarageSystem, Provisioner: provisioner,
	}

	_, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(access)})
	require.NoError(t, err)
	require.Equal(t, []string{accountID}, mockClient.deleteKeyCalls)
}

func TestBucketAccessClusterPreflightRejectsMixedClustersBeforeMutation(t *testing.T) {
	targetCluster := createReadyCluster()
	foreignShadow := createShadowBucket("foreign-bucket", "foreign")
	foreignShadow.Spec.ClusterRef.Name = "other-cluster"
	claim := &cosiv1alpha2.BucketClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "claim", Namespace: "tenant", UID: "claim-uid"},
		Status:     cosiv1alpha2.BucketClaimStatus{BoundBucketName: "bucket"},
	}
	bucket := &cosiv1alpha2.Bucket{
		ObjectMeta: metav1.ObjectMeta{Name: "bucket"},
		Spec: cosiv1alpha2.BucketSpec{
			DriverName: cosiTestDriver,
			BucketClaimRef: cosiv1alpha2.BucketClaimReference{
				Name: claim.Name, Namespace: claim.Namespace, UID: claim.UID,
			},
		},
		Status: cosiv1alpha2.BucketStatus{BucketID: "foreign-bucket"},
	}
	access := &cosiv1alpha2.BucketAccess{
		ObjectMeta: metav1.ObjectMeta{
			Name: "access", Namespace: claim.Namespace, UID: "access-uid",
			Finalizers: []string{GarageProtectionFinalizer},
		},
		Spec: cosiv1alpha2.BucketAccessSpec{
			Protocol: cosiv1alpha2.ObjectProtocolS3,
			BucketClaims: []cosiv1alpha2.BucketClaimAccess{{
				BucketClaimName: claim.Name, AccessMode: cosiv1alpha2.BucketAccessModeReadWrite,
				AccessSecretName: "credentials",
			}},
		},
		Status: cosiv1alpha2.BucketAccessStatus{
			DriverName: cosiTestDriver,
			Parameters: map[string]string{
				paramClusterRef: targetCluster.Name, paramClusterNamespace: targetCluster.Namespace,
			},
		},
	}
	kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(
		targetCluster, foreignShadow, claim, bucket, access,
	).Build()
	factoryCalled := false
	provisioner := NewProvisionerWithFactory(kubeClient, testGarageSystem,
		func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
			factoryCalled = true
			return newMockGarageClient(), nil
		})
	reconciler := &BucketAccessReconciler{
		Client: kubeClient, DriverName: cosiTestDriver, Namespace: testGarageSystem, Provisioner: provisioner,
	}

	_, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(access)})
	require.ErrorContains(t, err, "belongs to GarageCluster")
	require.False(t, factoryCalled)
	shadows := &garagev1beta1.GarageKeyList{}
	require.NoError(t, kubeClient.List(t.Context(), shadows, client.InNamespace(testGarageSystem)))
	require.Empty(t, shadows.Items)
}

func TestDeletingLegacyWinnerDoesNotRevokeAccountUsedByLiveLoser(t *testing.T) {
	const accountID = "GKshared"
	now := metav1.Now()
	legacy := shadowKey("backup", testMyCluster, testGarageSystem, nil, "")
	legacy.Namespace = testGarageSystem
	legacy.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] = garagev1beta1.COSIProvisioningStateBound
	legacy.Annotations[AnnotationCOSIAccountID] = accountID
	legacy.Labels[LabelCOSIAccountID] = truncateLabelValue(accountID)
	legacy.Status.AccessKeyID = accountID
	legacy.Status.KeyID = accountID
	winner := &cosiv1alpha2.BucketAccess{
		ObjectMeta: metav1.ObjectMeta{
			Name: "backup", Namespace: "ns-a", UID: "aaa", DeletionTimestamp: &now,
			Finalizers: []string{GarageProtectionFinalizer},
		},
		Status: cosiv1alpha2.BucketAccessStatus{DriverName: cosiTestDriver, AccountID: accountID},
	}
	other := &cosiv1alpha2.BucketAccess{
		ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "ns-b", UID: "bbb", Finalizers: []string{GarageProtectionFinalizer}},
		Status:     cosiv1alpha2.BucketAccessStatus{DriverName: cosiTestDriver, AccountID: accountID},
	}
	cluster := createReadyCluster()
	kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(legacy, winner, other, cluster).Build()
	mockClient := newMockGarageClient()
	mockClient.keys[accountID] = &garage.Key{AccessKeyID: accountID}
	provisioner := NewProvisionerWithFactory(kubeClient, testGarageSystem,
		func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
			return mockClient, nil
		})
	reconciler := &BucketAccessReconciler{Client: kubeClient, DriverName: cosiTestDriver, Namespace: testGarageSystem, Provisioner: provisioner}

	_, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(winner)})
	require.NoError(t, err)
	require.Empty(t, mockClient.deleteKeyCalls)

	require.NoError(t, kubeClient.Delete(t.Context(), other))
	_, err = reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(other)})
	require.NoError(t, err)
	require.Equal(t, []string{accountID}, mockClient.deleteKeyCalls, "the final deleting reference must revoke the legacy key")
}

func TestDeletingLegacyAccessCleansCanonicalDuplicateBeforeHandoff(t *testing.T) {
	const (
		legacyID    = "GKlegacy"
		canonicalID = "GKcanonical"
	)
	now := metav1.Now()
	legacy := shadowKey("backup", testMyCluster, testGarageSystem, nil, "")
	legacy.Namespace = testGarageSystem
	legacy.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] = garagev1beta1.COSIProvisioningStateBound
	legacy.Annotations[AnnotationCOSIAccountID] = legacyID
	legacy.Labels[LabelCOSIAccountID] = truncateLabelValue(legacyID)
	legacy.Status.AccessKeyID, legacy.Status.KeyID = legacyID, legacyID
	canonicalIdentity := "ba-access-uid"
	canonical := shadowKey(canonicalIdentity, testMyCluster, testGarageSystem, nil, "")
	canonical.Namespace = testGarageSystem
	canonical.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] = garagev1beta1.COSIProvisioningStateBound
	canonical.Annotations[AnnotationCOSIAccountID] = canonicalID
	canonical.Labels[LabelCOSIAccountID] = truncateLabelValue(canonicalID)
	canonical.Status.AccessKeyID, canonical.Status.KeyID = canonicalID, canonicalID
	access := &cosiv1alpha2.BucketAccess{
		ObjectMeta: metav1.ObjectMeta{
			Name: "backup", Namespace: "tenant", UID: "access-uid", DeletionTimestamp: &now,
			Finalizers: []string{GarageProtectionFinalizer},
		},
		Status: cosiv1alpha2.BucketAccessStatus{DriverName: cosiTestDriver, AccountID: legacyID},
	}
	cluster := createReadyCluster()
	kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(legacy, canonical, access, cluster).Build()
	mockClient := newMockGarageClient()
	mockClient.keys[legacyID] = &garage.Key{AccessKeyID: legacyID}
	mockClient.keys[canonicalID] = &garage.Key{AccessKeyID: canonicalID}
	provisioner := NewProvisionerWithFactory(kubeClient, testGarageSystem,
		func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
			return mockClient, nil
		})
	reconciler := &BucketAccessReconciler{
		Client: kubeClient, DriverName: cosiTestDriver, Namespace: testGarageSystem, Provisioner: provisioner,
	}

	request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(access)}
	result, err := reconciler.Reconcile(t.Context(), request)
	require.NoError(t, err)
	require.NotEqual(t, reconcile.Result{}, result)
	require.Equal(t, []string{canonicalID}, mockClient.deleteKeyCalls)
	require.True(t, apierrors.IsNotFound(kubeClient.Get(t.Context(), client.ObjectKeyFromObject(canonical), &garagev1beta1.GarageKey{})))
	require.NoError(t, kubeClient.Get(t.Context(), client.ObjectKeyFromObject(legacy), &garagev1beta1.GarageKey{}))

	_, err = reconciler.Reconcile(t.Context(), request)
	require.NoError(t, err)
	require.Equal(t, []string{canonicalID, legacyID}, mockClient.deleteKeyCalls)
	require.True(t, apierrors.IsNotFound(kubeClient.Get(t.Context(), client.ObjectKeyFromObject(legacy), &garagev1beta1.GarageKey{})))
}

func TestForeignSecretWinningCreateRaceBlocksProvisioning(t *testing.T) {
	secretKey := types.NamespacedName{Name: "credentials", Namespace: "tenant"}
	controller := true
	access := &cosiv1alpha2.BucketAccess{
		ObjectMeta: metav1.ObjectMeta{
			Name: "access", Namespace: secretKey.Namespace, UID: "access-uid",
			Finalizers: []string{GarageProtectionFinalizer},
		},
		Spec: cosiv1alpha2.BucketAccessSpec{
			Protocol: cosiv1alpha2.ObjectProtocolS3,
			BucketClaims: []cosiv1alpha2.BucketClaimAccess{{
				BucketClaimName: "claim", AccessSecretName: secretKey.Name,
			}},
		},
		Status: cosiv1alpha2.BucketAccessStatus{
			DriverName: cosiTestDriver,
			Parameters: map[string]string{paramClusterRef: testMyCluster, paramClusterNamespace: testGarageSystem},
		},
	}
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretKey.Name, Namespace: secretKey.Namespace,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1", Kind: "ConfigMap", Name: access.Name, UID: access.UID, Controller: &controller,
			}},
		},
		Data: map[string][]byte{"sentinel": []byte("foreign")},
	}
	baseClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(access).Build()
	kubeClient := &foreignSecretCreateRaceClient{Client: baseClient, target: secretKey, foreign: foreign}
	mockClient := newMockGarageClient()
	factoryCalled := false
	provisioner := NewProvisionerWithFactory(kubeClient, testGarageSystem,
		func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
			factoryCalled = true
			return mockClient, nil
		})
	reconciler := &BucketAccessReconciler{Client: kubeClient, DriverName: cosiTestDriver, Namespace: testGarageSystem, Provisioner: provisioner}

	_, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(access)})
	require.ErrorContains(t, err, "not controlled by this BucketAccess")
	require.True(t, kubeClient.wonRace)
	require.False(t, factoryCalled)
	require.Empty(t, mockClient.createKeyCalls)
	require.Empty(t, mockClient.importKeyCalls)
	require.Empty(t, mockClient.allowBucketKeyCalls)

	persisted := &corev1.Secret{}
	require.NoError(t, kubeClient.Get(t.Context(), secretKey, persisted))
	require.Equal(t, map[string][]byte{"sentinel": []byte("foreign")}, persisted.Data)
}

func TestPopulateSecretRejectsForeignReplacement(t *testing.T) {
	access := &cosiv1alpha2.BucketAccess{ObjectMeta: metav1.ObjectMeta{Name: "access", Namespace: "tenant", UID: "access-uid"}}
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: access.Namespace},
		Data:       map[string][]byte{"sentinel": []byte("foreign")},
	}
	kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(access, foreign).Build()
	reconciler := &BucketAccessReconciler{Client: kubeClient}

	err := reconciler.populateSecret(t.Context(), access, foreign.Name,
		BucketResult{GlobalAlias: "bucket", Endpoint: "https://s3.example", Region: "garage"},
		&AccessResult{AccessKeyID: "GKsecret", SecretAccessKey: "must-not-be-written"})
	require.ErrorContains(t, err, "not controlled by this BucketAccess")
	persisted := &corev1.Secret{}
	require.NoError(t, kubeClient.Get(t.Context(), client.ObjectKeyFromObject(foreign), persisted))
	require.Equal(t, map[string][]byte{"sentinel": []byte("foreign")}, persisted.Data)
}

func TestProvisionedBucketDeletionIgnoresLegacyInvalidParameters(t *testing.T) {
	now := metav1.Now()
	bucket := &cosiv1alpha2.Bucket{
		ObjectMeta: metav1.ObjectMeta{
			Name: "legacy-bucket", DeletionTimestamp: &now,
			Finalizers: []string{cosiv1alpha2.ProtectionFinalizer, GarageProtectionFinalizer},
		},
		Spec: cosiv1alpha2.BucketSpec{
			DriverName:     cosiTestDriver,
			DeletionPolicy: cosiv1alpha2.BucketDeletionPolicyDelete,
			Parameters: map[string]string{
				paramClusterRef:       testMyCluster,
				paramClusterNamespace: testGarageSystem,
				paramMaxSize:          "not-a-quantity",
				"removedLegacyField":  "formerly-accepted",
			},
		},
		Status: cosiv1alpha2.BucketStatus{BucketID: testBucketID},
	}
	shadow := createShadowBucket(testBucketID, bucket.Name)
	cluster := createReadyCluster()
	kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(bucket, shadow, cluster).Build()
	mockClient := newMockGarageClient()
	mockClient.buckets[testBucketID] = &garage.Bucket{ID: testBucketID}
	provisioner := NewProvisionerWithFactory(kubeClient, testGarageSystem,
		func(context.Context, client.Client, *garagev1beta2.GarageCluster) (GarageClient, error) {
			return mockClient, nil
		})
	reconciler := &BucketReconciler{Client: kubeClient, DriverName: cosiTestDriver, Namespace: testGarageSystem, Provisioner: provisioner}

	_, err := reconciler.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(bucket)})
	require.NoError(t, err)
	require.Equal(t, []string{testBucketID}, mockClient.deleteBucketCalls)
	require.True(t, apierrors.IsNotFound(kubeClient.Get(t.Context(), client.ObjectKeyFromObject(shadow), &garagev1beta1.GarageBucket{})))
	remaining := &cosiv1alpha2.Bucket{}
	if err := kubeClient.Get(t.Context(), client.ObjectKeyFromObject(bucket), remaining); err == nil {
		require.NotContains(t, remaining.Finalizers, GarageProtectionFinalizer)
		require.NotContains(t, remaining.Finalizers, cosiv1alpha2.ProtectionFinalizer)
	} else {
		require.True(t, apierrors.IsNotFound(err))
	}
}
