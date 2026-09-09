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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	cosiv1alpha2 "sigs.k8s.io/container-object-storage-interface/client/apis/objectstorage/v1alpha2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	garagev1beta1 "github.com/rajsinghtech/garage-operator/api/v1beta1"
)

func resolveBucketAccessIdentityForTest(
	mgr *ShadowManager, ctx context.Context, namespace, name, uid, accountID string,
) (string, bool, bool, error) {
	resolved, err := mgr.ResolveBucketAccessIdentity(ctx, namespace, name, uid, accountID, cosiTestDriver)
	return resolved.Identity, resolved.OwnsLegacyAccount, resolved.SharedLegacyAccount, err
}

func TestResolveBucketAccessIdentityScopesNewAccessesByUID(t *testing.T) {
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).Build()
	mgr := NewShadowManager(fakeClient, testGarageSystem)

	a, owner, shared, err := resolveBucketAccessIdentityForTest(mgr, t.Context(), "ns-a", "backup", "uid-a", "")
	require.NoError(t, err)
	require.False(t, owner)
	require.False(t, shared)
	b, owner, shared, err := resolveBucketAccessIdentityForTest(mgr, t.Context(), "ns-b", "backup", "uid-b", "")
	require.NoError(t, err)
	require.False(t, owner)
	require.False(t, shared)
	assert.Equal(t, "ba-uid-a", a)
	assert.Equal(t, "ba-uid-b", b)
	assert.NotEqual(t, ShadowResourceName(a), ShadowResourceName(b))
}

func TestResolveBucketAccessIdentityPrefersExistingCanonicalOverLegacy(t *testing.T) {
	canonical := shadowKey("ba-uid-a", testMyCluster, testGarageSystem, nil, "")
	canonical.Namespace = testGarageSystem
	legacy := shadowKey("backup", testMyCluster, testGarageSystem, nil, "")
	legacy.Namespace = testGarageSystem
	access := &cosiv1alpha2.BucketAccess{ObjectMeta: metav1.ObjectMeta{Namespace: "ns-a", Name: "backup", UID: "uid-a"}, Status: cosiv1alpha2.BucketAccessStatus{DriverName: cosiTestDriver}}
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(canonical, legacy, access).Build()
	mgr := NewShadowManager(fakeClient, testGarageSystem)

	identity, owner, shared, err := resolveBucketAccessIdentityForTest(mgr, t.Context(), access.Namespace, access.Name, string(access.UID), "")
	require.NoError(t, err)
	require.Equal(t, "ba-uid-a", identity)
	require.False(t, owner)
	require.False(t, shared)
}

func TestResolveBucketAccessIdentityFlagsCanonicalDuplicateOfKnownLegacyAccount(t *testing.T) {
	const legacyID = "GKlegacy"
	canonical := shadowKey("ba-uid-a", testMyCluster, testGarageSystem, nil, "")
	canonical.Namespace = testGarageSystem
	canonical.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] = garagev1beta1.COSIProvisioningStateBound
	canonical.Annotations[AnnotationCOSIAccountID] = "GKcanonical"
	canonical.Status.AccessKeyID = "GKcanonical"
	canonical.Status.KeyID = "GKcanonical"
	legacy := shadowKey("backup", testMyCluster, testGarageSystem, nil, "")
	legacy.Namespace = testGarageSystem
	legacy.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] = garagev1beta1.COSIProvisioningStateBound
	legacy.Annotations[AnnotationCOSIAccountID] = legacyID
	legacy.Status.AccessKeyID = legacyID
	legacy.Status.KeyID = legacyID
	access := &cosiv1alpha2.BucketAccess{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns-a", Name: "backup", UID: "uid-a"},
		Status: cosiv1alpha2.BucketAccessStatus{
			DriverName: cosiTestDriver, AccountID: legacyID,
		},
	}
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(canonical, legacy, access).Build()
	mgr := NewShadowManager(fakeClient, testGarageSystem)

	resolved, err := mgr.ResolveBucketAccessIdentity(
		t.Context(), access.Namespace, access.Name, string(access.UID), legacyID, cosiTestDriver,
	)
	require.NoError(t, err)
	assert.Equal(t, access.Name, resolved.Identity)
	assert.True(t, resolved.OwnsLegacyAccount)
	assert.Equal(t, "ba-uid-a", resolved.DuplicateCanonicalIdentity)
}

func TestResolveBucketAccessIdentityIgnoresForeignDriverCandidates(t *testing.T) {
	t.Run("bound account sharing", func(t *testing.T) {
		const accountID = "GKshared"
		legacy := shadowKey("backup", testMyCluster, testGarageSystem, nil, "")
		legacy.Namespace = testGarageSystem
		legacy.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] = garagev1beta1.COSIProvisioningStateBound
		legacy.Annotations[AnnotationCOSIAccountID] = accountID
		legacy.Status.AccessKeyID = accountID
		legacy.Status.KeyID = accountID
		current := &cosiv1alpha2.BucketAccess{
			ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "ours", UID: "bbb"},
			Status:     cosiv1alpha2.BucketAccessStatus{DriverName: cosiTestDriver, AccountID: accountID},
		}
		foreign := &cosiv1alpha2.BucketAccess{
			ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "foreign", UID: "aaa"},
			Status:     cosiv1alpha2.BucketAccessStatus{DriverName: "foreign.example", AccountID: accountID},
		}
		fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(legacy, current, foreign).Build()
		resolved, err := NewShadowManager(fakeClient, testGarageSystem).ResolveBucketAccessIdentity(
			t.Context(), current.Namespace, current.Name, string(current.UID), accountID, cosiTestDriver,
		)
		require.NoError(t, err)
		assert.Equal(t, current.Name, resolved.Identity)
		assert.True(t, resolved.OwnsLegacyAccount)
		assert.False(t, resolved.SharedLegacyAccount)
	})

	t.Run("pending reservation election", func(t *testing.T) {
		legacy := shadowKey("pending", testMyCluster, testGarageSystem, nil, "")
		legacy.Namespace = testGarageSystem
		current := &cosiv1alpha2.BucketAccess{
			ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "ours", UID: "bbb"},
			Status:     cosiv1alpha2.BucketAccessStatus{DriverName: cosiTestDriver},
		}
		foreign := &cosiv1alpha2.BucketAccess{
			ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "foreign", UID: "aaa"},
			Status:     cosiv1alpha2.BucketAccessStatus{DriverName: "foreign.example"},
		}
		fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(legacy, current, foreign).Build()
		resolved, err := NewShadowManager(fakeClient, testGarageSystem).ResolveBucketAccessIdentity(
			t.Context(), current.Namespace, current.Name, string(current.UID), "", cosiTestDriver,
		)
		require.NoError(t, err)
		assert.Equal(t, current.Name, resolved.Identity)
		assert.True(t, resolved.OwnsLegacyAccount)
	})
}

func TestResolveBucketAccessIdentityIsolatesAlreadyCollidedLegacyAccesses(t *testing.T) {
	const accountID = "GKshared"
	legacy := shadowKey("backup", testMyCluster, testGarageSystem, nil, "")
	legacy.Namespace = testGarageSystem
	legacy.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] = garagev1beta1.COSIProvisioningStateBound
	legacy.Annotations[AnnotationCOSIAccountID] = accountID
	legacy.Status.AccessKeyID = accountID
	legacy.Status.KeyID = accountID
	a := &cosiv1alpha2.BucketAccess{ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "ns-a", UID: "aaa"},
		Status: cosiv1alpha2.BucketAccessStatus{AccountID: accountID, DriverName: cosiTestDriver}}
	b := &cosiv1alpha2.BucketAccess{ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "ns-b", UID: "bbb"},
		Status: cosiv1alpha2.BucketAccessStatus{AccountID: accountID, DriverName: cosiTestDriver}}
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(legacy, a, b).Build()
	mgr := NewShadowManager(fakeClient, testGarageSystem)

	identity, owner, shared, err := resolveBucketAccessIdentityForTest(mgr, t.Context(), a.Namespace, a.Name, string(a.UID), accountID)
	require.NoError(t, err)
	assert.Equal(t, "backup", identity)
	assert.True(t, owner)
	assert.True(t, shared)
	identity, owner, shared, err = resolveBucketAccessIdentityForTest(mgr, t.Context(), b.Namespace, b.Name, string(b.UID), accountID)
	require.NoError(t, err)
	assert.Equal(t, "ba-bbb", identity)
	assert.False(t, owner)
	assert.True(t, shared)
}

func TestResolveBucketAccessIdentityRecoversUniquePendingLegacyCancellation(t *testing.T) {
	legacy := shadowKey("pending", testMyCluster, testGarageSystem, nil, "")
	legacy.Namespace = testGarageSystem
	access := &cosiv1alpha2.BucketAccess{ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "ns-a", UID: "uid-a"}, Status: cosiv1alpha2.BucketAccessStatus{DriverName: cosiTestDriver}}
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(legacy, access).Build()
	mgr := NewShadowManager(fakeClient, testGarageSystem)

	identity, owner, shared, err := resolveBucketAccessIdentityForTest(mgr, t.Context(), access.Namespace, access.Name, string(access.UID), "")
	require.NoError(t, err)
	assert.Equal(t, "pending", identity)
	assert.True(t, owner)
	assert.False(t, shared)
	persisted := &garagev1beta1.GarageKey{}
	require.NoError(t, fakeClient.Get(t.Context(), client.ObjectKeyFromObject(legacy), persisted))
	assert.Equal(t, string(access.UID), persisted.Annotations[annotationCOSILegacyAccessUID])
	done, err := mgr.RequestDeleteShadowKeyByName(t.Context(), identity)
	require.NoError(t, err)
	assert.False(t, done)
}

func TestResolveBucketAccessIdentityDoesNotReassignPendingLegacyWinner(t *testing.T) {
	legacy := shadowKey("pending", testMyCluster, testGarageSystem, nil, "")
	legacy.Namespace = testGarageSystem
	winner := &cosiv1alpha2.BucketAccess{ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "ns-z", UID: "zzz"}, Status: cosiv1alpha2.BucketAccessStatus{DriverName: cosiTestDriver}}
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(legacy, winner).Build()
	mgr := NewShadowManager(fakeClient, testGarageSystem)

	identity, owner, shared, err := resolveBucketAccessIdentityForTest(mgr, t.Context(), winner.Namespace, winner.Name, string(winner.UID), "")
	require.NoError(t, err)
	assert.Equal(t, "pending", identity)
	assert.True(t, owner)
	assert.False(t, shared)

	later := &cosiv1alpha2.BucketAccess{ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "ns-a", UID: "aaa"}, Status: cosiv1alpha2.BucketAccessStatus{DriverName: cosiTestDriver}}
	require.NoError(t, fakeClient.Create(t.Context(), later))
	identity, owner, shared, err = resolveBucketAccessIdentityForTest(mgr, t.Context(), later.Namespace, later.Name, string(later.UID), "")
	require.NoError(t, err)
	assert.Equal(t, "ba-aaa", identity)
	assert.False(t, owner)
	assert.False(t, shared)

	identity, owner, shared, err = resolveBucketAccessIdentityForTest(mgr, t.Context(), winner.Namespace, winner.Name, string(winner.UID), "")
	require.NoError(t, err)
	assert.Equal(t, "pending", identity)
	assert.True(t, owner)
	assert.False(t, shared)
}

func TestResolveBucketAccessIdentityClaimsAmbiguousPendingLegacyWinner(t *testing.T) {
	legacy := shadowKey("pending", testMyCluster, testGarageSystem, nil, "")
	legacy.Namespace = testGarageSystem
	winner := &cosiv1alpha2.BucketAccess{ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "ns-a", UID: "aaa"}, Status: cosiv1alpha2.BucketAccessStatus{DriverName: cosiTestDriver}}
	other := &cosiv1alpha2.BucketAccess{ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "ns-b", UID: "bbb"}, Status: cosiv1alpha2.BucketAccessStatus{DriverName: cosiTestDriver}}
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(legacy, winner, other).Build()
	mgr := NewShadowManager(fakeClient, testGarageSystem)

	identity, owner, shared, err := resolveBucketAccessIdentityForTest(mgr, t.Context(), other.Namespace, other.Name, string(other.UID), "")
	require.NoError(t, err)
	assert.Equal(t, "ba-bbb", identity)
	assert.False(t, owner)
	assert.False(t, shared)

	identity, owner, shared, err = resolveBucketAccessIdentityForTest(mgr, t.Context(), winner.Namespace, winner.Name, string(winner.UID), "")
	require.NoError(t, err)
	assert.Equal(t, "pending", identity)
	assert.True(t, owner)
	assert.False(t, shared)

	persisted := &garagev1beta1.GarageKey{}
	require.NoError(t, fakeClient.Get(t.Context(), client.ObjectKeyFromObject(legacy), persisted))
	assert.Equal(t, string(winner.UID), persisted.Annotations[annotationCOSILegacyAccessUID])
}

func TestResolveBucketAccessIdentityWinnerDeletionKeepsSharedLegacyAccount(t *testing.T) {
	const accountID = "GKshared"
	now := metav1.Now()
	legacy := shadowKey("backup", testMyCluster, testGarageSystem, nil, "")
	legacy.Namespace = testGarageSystem
	legacy.Annotations[garagev1beta1.AnnotationCOSIProvisioningState] = garagev1beta1.COSIProvisioningStateBound
	legacy.Annotations[AnnotationCOSIAccountID] = accountID
	legacy.Status.AccessKeyID = accountID
	legacy.Status.KeyID = accountID
	winner := &cosiv1alpha2.BucketAccess{
		ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "ns-a", UID: "aaa", DeletionTimestamp: &now, Finalizers: []string{GarageProtectionFinalizer}},
		Status:     cosiv1alpha2.BucketAccessStatus{AccountID: accountID, DriverName: cosiTestDriver},
	}
	other := &cosiv1alpha2.BucketAccess{ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "ns-b", UID: "bbb"},
		Status: cosiv1alpha2.BucketAccessStatus{AccountID: accountID, DriverName: cosiTestDriver}}
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(legacy, winner, other).Build()
	mgr := NewShadowManager(fakeClient, testGarageSystem)

	identity, owner, shared, err := resolveBucketAccessIdentityForTest(mgr, t.Context(), winner.Namespace, winner.Name, string(winner.UID), accountID)
	require.NoError(t, err)
	assert.Equal(t, "ba-aaa", identity)
	assert.False(t, owner)
	assert.True(t, shared, "the first deletion must not revoke an account still used by another live BucketAccess")
}

func TestShadowResourceName(t *testing.T) {
	tests := []struct {
		cosiName string
	}{
		{testMyBucket},
		{"default-my-bucket"},
		{"my-very-long-bucket-name-that-exceeds-normal-limits"},
	}

	for _, tt := range tests {
		t.Run(tt.cosiName, func(t *testing.T) {
			got := ShadowResourceName(tt.cosiName)
			// Should start with "cosi-" prefix
			assert.True(t, strings.HasPrefix(got, "cosi-"), "should have cosi- prefix")
			// Should be 63 chars or less (K8s limit)
			assert.LessOrEqual(t, len(got), 63, "should be <= 63 chars")
			// Same input should always produce same output
			assert.Equal(t, got, ShadowResourceName(tt.cosiName), "should be deterministic")
		})
	}

	// Different inputs should produce different outputs
	name1 := ShadowResourceName("bucket-a")
	name2 := ShadowResourceName("bucket-b")
	assert.NotEqual(t, name1, name2, "different inputs should produce different names")
}

func TestShadowResourceLabels(t *testing.T) {
	t.Run("bucket labels", func(t *testing.T) {
		labels := ShadowBucketLabels("my-bucket-claim")

		assert.Equal(t, "true", labels[LabelCOSIManaged])
		assert.Equal(t, "my-bucket-claim", labels[LabelCOSIBucketClaim])
	})

	t.Run("key labels", func(t *testing.T) {
		labels := ShadowKeyLabels("my-bucket-access")

		assert.Equal(t, "true", labels[LabelCOSIManaged])
		assert.Equal(t, "my-bucket-access", labels[LabelCOSIBucketAccess])
	})
}

func TestLongCOSINameProducesValidHashedLabel(t *testing.T) {
	name := strings.Repeat("a", 62) + "-tail"
	value := truncateLabelValue(name)
	assert.Len(t, value, len("sha256-")+32)
	assert.NotEqual(t, '-', value[len(value)-1])
}

func TestReservationsInstallCleanupFinalizersOnInitialCreate(t *testing.T) {
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).Build()
	mgr := NewShadowManager(fakeClient, testGarageSystem)

	bucket, created, err := mgr.ReserveShadowBucket(context.Background(), "claim", testMyCluster,
		testGarageSystem, defaultBucketParams())
	require.NoError(t, err)
	require.True(t, created)
	assert.Contains(t, bucket.Finalizers, garagev1beta1.GarageBucketFinalizer)

	key, created, err := mgr.ReserveShadowKey(context.Background(), "access", testMyCluster,
		testGarageSystem, nil, "")
	require.NoError(t, err)
	require.True(t, created)
	assert.Contains(t, key.Finalizers, garagev1beta1.GarageKeyFinalizer)
}

func TestShadowReservationsRestoreMissingCorrelationLabels(t *testing.T) {
	t.Run("bucket reservation and bind", func(t *testing.T) {
		bucket := shadowBucket("claim", testMyCluster, testGarageSystem, nil)
		bucket.Namespace = testGarageSystem
		bucket.Labels["example.com/keep"] = "yes"
		delete(bucket.Labels, LabelCOSIBucketClaim)
		client := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(bucket).Build()
		mgr := NewShadowManager(client, testGarageSystem)

		reserved, created, err := mgr.ReserveShadowBucket(t.Context(), "claim", testMyCluster, testGarageSystem, nil)
		require.NoError(t, err)
		require.False(t, created)
		require.Equal(t, "claim", reserved.Labels[LabelCOSIBucketClaim])
		require.Equal(t, "yes", reserved.Labels["example.com/keep"])

		delete(reserved.Labels, LabelCOSIBucketClaim)
		bound, err := mgr.BindShadowBucket(t.Context(), reserved, testBucketID, nil)
		require.NoError(t, err)
		require.Equal(t, "claim", bound.Labels[LabelCOSIBucketClaim])
		require.Equal(t, "yes", bound.Labels["example.com/keep"])
	})

	t.Run("key reservation and bind", func(t *testing.T) {
		key := shadowKey("access", testMyCluster, testGarageSystem, nil, "")
		key.Namespace = testGarageSystem
		key.Labels["example.com/keep"] = "yes"
		delete(key.Labels, LabelCOSIBucketAccess)
		client := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(key).Build()
		mgr := NewShadowManager(client, testGarageSystem)

		reserved, created, err := mgr.ReserveShadowKey(t.Context(), "access", testMyCluster, testGarageSystem, nil, "")
		require.NoError(t, err)
		require.False(t, created)
		require.Equal(t, "access", reserved.Labels[LabelCOSIBucketAccess])
		require.Equal(t, "yes", reserved.Labels["example.com/keep"])

		delete(reserved.Labels, LabelCOSIBucketAccess)
		bound, err := mgr.BindShadowKey(t.Context(), reserved, testGKTestKey, nil, "")
		require.NoError(t, err)
		require.Equal(t, "access", bound.Labels[LabelCOSIBucketAccess])
		require.Equal(t, "yes", bound.Labels["example.com/keep"])
	})
}

func TestShadowBucketCleanupRefusesOutOfScopeCorrelation(t *testing.T) {
	bucket := shadowBucket("claim", testMyCluster, testGarageSystem, nil)
	bucket.Namespace = testGarageSystem
	bucket.Status.BucketID = testBucketID
	bucket.Annotations[AnnotationCOSIBucketID] = testBucketID
	bucket.Labels[LabelCOSIManaged] = paramTrue
	bucket.Labels[LabelCOSIBucketID] = truncateLabelValue(testBucketID)
	bucket.Labels[LabelCOSIBucketClaim] = "other-claim"
	client := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(bucket).Build()
	mgr := NewShadowManager(client, testGarageSystem)

	owned, err := mgr.OwnsShadowBucket(t.Context(), "claim", testBucketID)
	require.NoError(t, err)
	require.False(t, owned)
}

func TestForgetShadowBucketUpgradesLegacyExactIdentityBeforeRetain(t *testing.T) {
	legacy := shadowBucket("claim", testMyCluster, testGarageSystem, nil)
	legacy.Namespace = testGarageSystem
	legacy.UID = "legacy-shadow-uid"
	delete(legacy.Annotations, annotationCOSIReservationOwner)
	delete(legacy.Annotations, garagev1beta1.AnnotationCOSIProvisioningState)
	legacy.Annotations[AnnotationCOSIBucketID] = testBucketID
	fakeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(legacy).Build()
	mgr := NewShadowManager(fakeClient, testGarageSystem)

	done, err := mgr.ForgetShadowBucketByName(t.Context(), "claim", testBucketID)
	require.NoError(t, err)
	require.False(t, done)
	persisted := &garagev1beta1.GarageBucket{}
	require.NoError(t, fakeClient.Get(t.Context(), client.ObjectKeyFromObject(legacy), persisted))
	require.Equal(t, testBucketID, persisted.Status.BucketID)
	require.Equal(t, garagev1beta1.COSIProvisioningStateBound, persisted.Annotations[garagev1beta1.AnnotationCOSIProvisioningState])
	require.Equal(t, "claim", persisted.Annotations[annotationCOSIReservationOwner])
	require.NotEmpty(t, persisted.Annotations[garagev1beta1.AnnotationCOSIRetain])
	require.False(t, persisted.DeletionTimestamp.IsZero())
}

func TestCreateShadowKeyWithID_StoresServiceAccountName(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := newCOSIClientBuilder().WithScheme(scheme).Build()
	mgr := NewShadowManager(fakeClient, "garage-system")

	key, err := mgr.CreateShadowKeyWithID(context.Background(), "my-access", "GKabc", "my-cluster", "garage-system",
		[]BucketPermission{{BucketID: testBucket1, Read: true, Write: true}},
		"my-serviceaccount",
	)
	require.NoError(t, err)
	assert.Equal(t, "my-serviceaccount", key.Annotations[AnnotationCOSIServiceAccountName])
}

func TestShadowBucketIDLookupIgnoresForgedMetadata(t *testing.T) {
	makeBucket := func(name, uid, cluster string, authoritative bool) *garagev1beta1.GarageBucket {
		bucket := &garagev1beta1.GarageBucket{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: testGarageSystem, UID: types.UID(uid),
				Labels: map[string]string{
					LabelCOSIManaged: paramTrue, LabelCOSIBucketID: truncateLabelValue(testBucketID),
				},
				Annotations: map[string]string{
					AnnotationCOSIBucketID:                        testBucketID,
					annotationCOSIReservationOwner:                name,
					garagev1beta1.AnnotationCOSIProvisioningState: garagev1beta1.COSIProvisioningStateBound,
				},
			},
			Spec: garagev1beta1.GarageBucketSpec{
				ClusterRef:  garagev1beta1.ClusterReference{Name: cluster, Namespace: testGarageSystem},
				GlobalAlias: name,
			},
		}
		if authoritative {
			bucket.Status.BucketID = testBucketID
		}
		return bucket
	}
	forged := makeBucket("a-forged", "forged-bucket-uid", "foreign-cluster", false)
	real := makeBucket("z-real", "real-bucket-uid", testMyCluster, true)
	kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(forged, real).Build()
	mgr := NewShadowManager(kubeClient, testGarageSystem)

	name, namespace, err := mgr.GetShadowBucketClusterRef(t.Context(), testBucketID)
	require.NoError(t, err)
	require.Equal(t, testMyCluster, name)
	require.Equal(t, testGarageSystem, namespace)
	resolvedName, err := mgr.GetShadowBucketNameByID(t.Context(), testBucketID)
	require.NoError(t, err)
	require.Equal(t, real.Name, resolvedName)
	alias, err := mgr.GetShadowBucketGlobalAliasByID(t.Context(), testBucketID)
	require.NoError(t, err)
	require.Equal(t, real.Spec.GlobalAlias, alias)
	require.NoError(t, mgr.DeleteShadowBucketByID(t.Context(), testBucketID))
	require.True(t, apierrors.IsNotFound(kubeClient.Get(t.Context(), client.ObjectKeyFromObject(real), &garagev1beta1.GarageBucket{})))
	require.NoError(t, kubeClient.Get(t.Context(), client.ObjectKeyFromObject(forged), &garagev1beta1.GarageBucket{}))
}

func TestShadowBucketIDLookupFailsClosedOnMultipleAuthoritativeShadows(t *testing.T) {
	objects := make([]client.Object, 0, 2)
	for _, name := range []string{"first", "second"} {
		objects = append(objects, &garagev1beta1.GarageBucket{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: testGarageSystem, UID: types.UID(name + "-uid"),
				Labels: map[string]string{LabelCOSIManaged: paramTrue, LabelCOSIBucketID: truncateLabelValue(testBucketID)},
				Annotations: map[string]string{
					AnnotationCOSIBucketID:                        testBucketID,
					annotationCOSIReservationOwner:                name,
					garagev1beta1.AnnotationCOSIProvisioningState: garagev1beta1.COSIProvisioningStateBound,
				},
			},
			Status: garagev1beta1.GarageBucketStatus{BucketID: testBucketID},
		})
	}
	kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(objects...).Build()
	mgr := NewShadowManager(kubeClient, testGarageSystem)

	_, _, err := mgr.GetShadowBucketClusterRef(t.Context(), testBucketID)
	require.ErrorContains(t, err, "multiple authoritative")
	require.ErrorContains(t, mgr.DeleteShadowBucketByID(t.Context(), testBucketID), "multiple authoritative")
	for _, object := range objects {
		require.NoError(t, kubeClient.Get(t.Context(), client.ObjectKeyFromObject(object), &garagev1beta1.GarageBucket{}))
	}
}

func TestShadowKeyIDLookupIgnoresForgedMetadataAndFailsOnAmbiguity(t *testing.T) {
	makeKey := func(name, uid, cluster string, authoritative bool) *garagev1beta1.GarageKey {
		key := &garagev1beta1.GarageKey{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: testGarageSystem, UID: types.UID(uid),
				Labels: map[string]string{
					LabelCOSIManaged: paramTrue, LabelCOSIAccountID: truncateLabelValue(testGKTestKey),
				},
				Annotations: map[string]string{
					AnnotationCOSIAccountID:                       testGKTestKey,
					annotationCOSIReservationOwner:                name,
					garagev1beta1.AnnotationCOSIProvisioningState: garagev1beta1.COSIProvisioningStateBound,
				},
			},
			Spec: garagev1beta1.GarageKeySpec{
				ClusterRef: garagev1beta1.ClusterReference{Name: cluster, Namespace: testGarageSystem},
			},
		}
		if authoritative {
			key.Status.AccessKeyID, key.Status.KeyID = testGKTestKey, testGKTestKey
		}
		return key
	}
	t.Run("forged metadata is ignored", func(t *testing.T) {
		forged := makeKey("a-forged", "forged-key-uid", "foreign-cluster", false)
		real := makeKey("z-real", "real-key-uid", testMyCluster, true)
		kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(forged, real).Build()
		mgr := NewShadowManager(kubeClient, testGarageSystem)

		name, namespace, err := mgr.GetShadowKeyClusterRef(t.Context(), testGKTestKey)
		require.NoError(t, err)
		require.Equal(t, testMyCluster, name)
		require.Equal(t, testGarageSystem, namespace)
		require.NoError(t, mgr.DeleteShadowKeyByID(t.Context(), testGKTestKey))
		require.True(t, apierrors.IsNotFound(kubeClient.Get(t.Context(), client.ObjectKeyFromObject(real), &garagev1beta1.GarageKey{})))
		require.NoError(t, kubeClient.Get(t.Context(), client.ObjectKeyFromObject(forged), &garagev1beta1.GarageKey{}))
	})

	t.Run("multiple authoritative shadows fail closed", func(t *testing.T) {
		first := makeKey("first", "first-uid", testMyCluster, true)
		second := makeKey("second", "second-uid", "other-cluster", true)
		kubeClient := newCOSIClientBuilder().WithScheme(newTestScheme()).WithObjects(first, second).Build()
		mgr := NewShadowManager(kubeClient, testGarageSystem)

		_, _, err := mgr.GetShadowKeyClusterRef(t.Context(), testGKTestKey)
		require.ErrorContains(t, err, "multiple authoritative")
		require.ErrorContains(t, mgr.DeleteShadowKeyByID(t.Context(), testGKTestKey), "multiple authoritative")
		for _, object := range []client.Object{first, second} {
			require.NoError(t, kubeClient.Get(t.Context(), client.ObjectKeyFromObject(object), &garagev1beta1.GarageKey{}))
		}
	})
}

func TestCreateShadowResourcesRefuseNameCollision(t *testing.T) {
	for name, existing := range map[string]any{
		"bucket": &garagev1beta1.GarageBucket{ObjectMeta: metav1.ObjectMeta{
			Name: ShadowResourceName("claim"), Namespace: testGarageSystem,
		}},
		"key": &garagev1beta1.GarageKey{ObjectMeta: metav1.ObjectMeta{
			Name: ShadowResourceName("access"), Namespace: testGarageSystem,
		}},
	} {
		t.Run(name, func(t *testing.T) {
			scheme := newTestScheme()
			builder := newCOSIClientBuilder().WithScheme(scheme)
			switch object := existing.(type) {
			case *garagev1beta1.GarageBucket:
				builder = builder.WithObjects(object.DeepCopy())
			case *garagev1beta1.GarageKey:
				builder = builder.WithObjects(object.DeepCopy())
			}
			mgr := NewShadowManager(builder.Build(), testGarageSystem)
			if name == "bucket" {
				_, err := mgr.CreateShadowBucketWithID(context.Background(), "claim", testBucketID,
					testMyCluster, testGarageSystem, defaultBucketParams())
				require.ErrorContains(t, err, "refusing to overwrite non-COSI")
			} else {
				_, err := mgr.CreateShadowKeyWithID(context.Background(), "access", testGKTestKey,
					testMyCluster, testGarageSystem, nil, "")
				require.ErrorContains(t, err, "refusing to overwrite non-COSI")
			}
		})
	}
}
