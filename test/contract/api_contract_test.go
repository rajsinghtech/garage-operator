//go:build garagecontract

package contract

import (
	"context"
	"testing"

	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// readyNode starts a one-node cluster with an applied layout, ready for
// bucket and key table writes.
func readyNode(t *testing.T) *node {
	t.Helper()
	nodes := startCluster(t, 1, 1)
	assignAndApply(t, nodes[0], nodes[0].id)
	waitLayoutReady(t, nodes[0])
	return nodes[0]
}

// The bucket controller only falls back to alias lookup or creation on a
// genuine 404 (a transient error must never look like "gone", or it creates
// duplicate buckets); deletes and denies tolerate 404 as already done.
func TestContract_MissingObjectsAreNotFound(t *testing.T) {
	c := readyNode(t).client
	ctx := context.Background()
	b, err := c.CreateBucket(ctx, garage.CreateBucketRequest{GlobalAlias: "contract-notfound"})
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.CreateKey(ctx, "contract-notfound")
	if err != nil {
		t.Fatal(err)
	}
	unknownBucket, unknownKey := randomHex(t, 32), "GK"+randomHex(t, 12)
	checks := []struct {
		what string
		call func() error
	}{
		{"GetBucket by unknown ID", func() error { _, e := c.GetBucket(ctx, garage.GetBucketRequest{ID: unknownBucket}); return e }},
		{"GetBucket by unknown global alias", func() error {
			_, e := c.GetBucket(ctx, garage.GetBucketRequest{GlobalAlias: "contract-no-such-alias"})
			return e
		}},
		{"DeleteBucket unknown", func() error { return c.DeleteBucket(ctx, unknownBucket) }},
		{"GetKey unknown", func() error { _, e := c.GetKey(ctx, garage.GetKeyRequest{ID: unknownKey}); return e }},
		{"DeleteKey unknown", func() error { return c.DeleteKey(ctx, unknownKey) }},
		{"AddBucketAlias on unknown bucket", func() error {
			_, e := c.AddBucketAlias(ctx, garage.AddBucketAliasRequest{BucketID: unknownBucket, GlobalAlias: "contract-x"})
			return e
		}},
		{"RemoveBucketAlias on unknown bucket", func() error {
			_, e := c.RemoveBucketAlias(ctx, garage.RemoveBucketAliasRequest{BucketID: unknownBucket, GlobalAlias: "contract-notfound"})
			return e
		}},
		{"AddBucketAlias local for unknown key", func() error {
			_, e := c.AddBucketAlias(ctx, garage.AddBucketAliasRequest{BucketID: b.ID, LocalAlias: "contract-local", AccessKeyID: unknownKey})
			return e
		}},
		{"DenyBucketKey unknown key", func() error {
			_, e := c.DenyBucketKey(ctx, garage.DenyBucketKeyRequest{BucketID: b.ID, AccessKeyID: unknownKey, Permissions: garage.BucketKeyPerms{Read: true}})
			return e
		}},
		{"DenyBucketKey unknown bucket", func() error {
			_, e := c.DenyBucketKey(ctx, garage.DenyBucketKeyRequest{BucketID: unknownBucket, AccessKeyID: k.AccessKeyID, Permissions: garage.BucketKeyPerms{Read: true}})
			return e
		}},
		{"GetAdminTokenInfo unknown", func() error { _, e := c.GetAdminTokenInfo(ctx, randomHex(t, 12), ""); return e }},
		{"DeleteAdminToken unknown", func() error { return c.DeleteAdminToken(ctx, randomHex(t, 12)) }},
	}
	for _, ck := range checks {
		err := ck.call()
		if !garage.IsNotFound(err) {
			t.Errorf("%s: want 404 (IsNotFound), got status %d: %v", ck.what, apiStatus(err), err)
		}
	}
}

// Global alias semantics the bucket controller's add-then-remove rename and
// creation paths rely on.
func TestContract_GlobalBucketAliases(t *testing.T) {
	c := readyNode(t).client
	ctx := context.Background()
	b1, err := c.CreateBucket(ctx, garage.CreateBucketRequest{GlobalAlias: "contract-one"})
	if err != nil {
		t.Fatal(err)
	}
	b2, err := c.CreateBucket(ctx, garage.CreateBucketRequest{GlobalAlias: "contract-two"})
	if err != nil {
		t.Fatal(err)
	}

	// Creating with a taken alias is a 409 Conflict.
	_, err = c.CreateBucket(ctx, garage.CreateBucketRequest{GlobalAlias: "contract-one"})
	if !garage.IsConflict(err) {
		t.Fatalf("CreateBucket with a taken global alias: want 409, got %d: %v", apiStatus(err), err)
	}

	// Re-adding an alias the bucket already has is an idempotent success.
	if _, err := c.AddBucketAlias(ctx, garage.AddBucketAliasRequest{BucketID: b1.ID, GlobalAlias: "contract-one"}); err != nil {
		t.Fatalf("re-adding a bucket's own global alias: %v", err)
	}

	// An alias owned by another bucket is rejected with 400, NOT 409: the
	// controller's IsConflict branches never see it and surface the error
	// as-is. Either way the alias must not move.
	_, err = c.AddBucketAlias(ctx, garage.AddBucketAliasRequest{BucketID: b2.ID, GlobalAlias: "contract-one"})
	wantStatus(t, "AddBucketAlias with another bucket's alias", err, 400)
	wantMessage(t, "AddBucketAlias with another bucket's alias", err, "different bucket")
	if got, err := c.GetBucket(ctx, garage.GetBucketRequest{GlobalAlias: "contract-one"}); err != nil || got.ID != b1.ID {
		t.Fatalf("contested alias moved: %+v %v", got, err)
	}

	// The last global alias cannot be removed (add-before-remove renames).
	_, err = c.RemoveBucketAlias(ctx, garage.RemoveBucketAliasRequest{BucketID: b1.ID, GlobalAlias: "contract-one"})
	wantStatus(t, "removing a bucket's only global alias", err, 400)

	// Rename: add the new alias, then remove the old one.
	if _, err := c.AddBucketAlias(ctx, garage.AddBucketAliasRequest{BucketID: b1.ID, GlobalAlias: "contract-one-renamed"}); err != nil {
		t.Fatal(err)
	}
	updated, err := c.RemoveBucketAlias(ctx, garage.RemoveBucketAliasRequest{BucketID: b1.ID, GlobalAlias: "contract-one"})
	if err != nil {
		t.Fatalf("removing the old alias after adding the new one: %v", err)
	}
	if updated.ID != b1.ID || len(updated.GlobalAliases) != 1 || updated.GlobalAliases[0] != "contract-one-renamed" {
		t.Fatalf("RemoveBucketAlias must return the updated bucket, got %+v", updated)
	}

	// Removing an alias the bucket does not have is a 500, not a 404. The
	// controllers therefore only remove aliases they just observed on the
	// bucket; their IsNotFound tolerance does not cover this case.
	_, err = c.RemoveBucketAlias(ctx, garage.RemoveBucketAliasRequest{BucketID: b1.ID, GlobalAlias: "contract-one"})
	if garage.IsNotFound(err) || apiStatus(err) != 500 {
		t.Fatalf("removing an absent global alias: want a non-404 500, got %d: %v", apiStatus(err), err)
	}
	_, err = c.RemoveBucketAlias(ctx, garage.RemoveBucketAliasRequest{BucketID: b2.ID, GlobalAlias: "contract-one-renamed"})
	if garage.IsNotFound(err) || apiStatus(err) != 500 {
		t.Fatalf("removing another bucket's alias: want a non-404 500, got %d: %v", apiStatus(err), err)
	}
}

// Local (per-key) alias semantics used by spec.localAliases reconciliation.
func TestContract_LocalBucketAliases(t *testing.T) {
	c := readyNode(t).client
	ctx := context.Background()
	b1, err := c.CreateBucket(ctx, garage.CreateBucketRequest{GlobalAlias: "contract-local-one"})
	if err != nil {
		t.Fatal(err)
	}
	b2, err := c.CreateBucket(ctx, garage.CreateBucketRequest{GlobalAlias: "contract-local-two"})
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.CreateKey(ctx, "contract-local")
	if err != nil {
		t.Fatal(err)
	}
	add := func(bucketID string) error {
		_, err := c.AddBucketAlias(ctx, garage.AddBucketAliasRequest{BucketID: bucketID, LocalAlias: "mine", AccessKeyID: k.AccessKeyID})
		return err
	}
	if err := add(b1.ID); err != nil {
		t.Fatal(err)
	}
	if err := add(b1.ID); err != nil {
		t.Fatalf("re-adding the same local alias must be idempotent: %v", err)
	}
	err = add(b2.ID)
	wantStatus(t, "local alias taken by another bucket", err, 400)
	got, err := c.GetBucket(ctx, garage.GetBucketRequest{ID: b1.ID})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ki := range got.Keys {
		if ki.AccessKeyID == k.AccessKeyID {
			for _, a := range ki.BucketLocalAliases {
				found = found || a == "mine"
			}
		}
	}
	if !found {
		t.Fatalf("GetBucket must list the key's local alias under keys[].bucketLocalAliases: %+v", got.Keys)
	}
	_, err = c.RemoveBucketAlias(ctx, garage.RemoveBucketAliasRequest{BucketID: b1.ID, LocalAlias: "absent", AccessKeyID: k.AccessKeyID})
	if garage.IsNotFound(err) || apiStatus(err) != 500 {
		t.Fatalf("removing an absent local alias: want a non-404 500, got %d: %v", apiStatus(err), err)
	}
	if _, err := c.RemoveBucketAlias(ctx, garage.RemoveBucketAliasRequest{BucketID: b1.ID, LocalAlias: "mine", AccessKeyID: k.AccessKeyID}); err != nil {
		t.Fatalf("removing a local alias (the bucket still has a global one): %v", err)
	}
}

// Deterministic key import: a live duplicate and a deleted (tombstoned) ID
// both return 409; GetKey then distinguishes them (200 vs 404). Malformed
// material is a 400 the key controller reports as an import rejection.
func TestContract_KeyImportConflictsAndTombstones(t *testing.T) {
	c := readyNode(t).client
	ctx := context.Background()
	id, secret := "GK"+randomHex(t, 12), randomHex(t, 32)
	imported, err := c.ImportKey(ctx, garage.ImportKeyRequest{AccessKeyID: id, SecretAccessKey: secret, Name: "contract-import"})
	if err != nil {
		t.Fatal(err)
	}
	// ImportKey does not echo the secret (v2.0.0-v2.4.1 return it empty), so
	// callers must keep their own copy; it must never return different material.
	if imported.AccessKeyID != id || (imported.SecretAccessKey != "" && imported.SecretAccessKey != secret) {
		t.Fatalf("ImportKey returned different material: id=%s", imported.AccessKeyID)
	}
	if stored, err := c.GetKey(ctx, garage.GetKeyRequest{ID: id, ShowSecretKey: true}); err != nil || stored.SecretAccessKey != secret {
		t.Fatalf("GetKey(showSecretKey) must return the imported secret: %v", err)
	}

	_, err = c.ImportKey(ctx, garage.ImportKeyRequest{AccessKeyID: id, SecretAccessKey: secret, Name: "contract-import"})
	if !garage.IsConflict(err) {
		t.Fatalf("re-importing a live key: want 409, got %d: %v", apiStatus(err), err)
	}
	live, err := c.GetKey(ctx, garage.GetKeyRequest{ID: id, ShowSecretKey: true})
	if err != nil || live.SecretAccessKey != secret {
		t.Fatalf("GetKey(showSecretKey) on a live conflict must return the stored secret: %+v %v", live, err)
	}

	if err := c.DeleteKey(ctx, id); err != nil {
		t.Fatal(err)
	}
	_, err = c.ImportKey(ctx, garage.ImportKeyRequest{AccessKeyID: id, SecretAccessKey: secret, Name: "contract-import"})
	if !garage.IsConflict(err) {
		t.Fatalf("re-importing a deleted key ID: want 409 (tombstone), got %d: %v", apiStatus(err), err)
	}
	if _, err := c.GetKey(ctx, garage.GetKeyRequest{ID: id}); !garage.IsNotFound(err) {
		t.Fatalf("GetKey on a tombstoned ID: want 404, got %d: %v", apiStatus(err), err)
	}

	for _, bad := range []garage.ImportKeyRequest{
		{AccessKeyID: "bad", SecretAccessKey: secret},
		{AccessKeyID: "GK" + randomHex(t, 12), SecretAccessKey: "short"},
	} {
		if _, err := c.ImportKey(ctx, bad); !garage.IsBadRequest(err) {
			t.Fatalf("malformed import %q: want 400, got %d: %v", bad.AccessKeyID, apiStatus(err), err)
		}
	}
}

// Bucket/key grants round-trip through GetBucket and GetKey, and deny revokes.
func TestContract_BucketKeyPermissions(t *testing.T) {
	c := readyNode(t).client
	ctx := context.Background()
	b, err := c.CreateBucket(ctx, garage.CreateBucketRequest{GlobalAlias: "contract-perms"})
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.CreateKey(ctx, "contract-perms")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AllowBucketKey(ctx, garage.AllowBucketKeyRequest{BucketID: b.ID, AccessKeyID: k.AccessKeyID, Permissions: garage.BucketKeyPerms{Read: true, Write: true}}); err != nil {
		t.Fatal(err)
	}
	perms := func() (garage.BucketKeyPerms, bool) {
		got, err := c.GetBucket(ctx, garage.GetBucketRequest{ID: b.ID})
		if err != nil {
			t.Fatal(err)
		}
		for _, ki := range got.Keys {
			if ki.AccessKeyID == k.AccessKeyID {
				return ki.Permissions, true
			}
		}
		return garage.BucketKeyPerms{}, false
	}
	if p, ok := perms(); !ok || !p.Read || !p.Write || p.Owner {
		t.Fatalf("after allow read+write: %+v listed=%v", p, ok)
	}
	key, err := c.GetKey(ctx, garage.GetKeyRequest{ID: k.AccessKeyID})
	if err != nil || len(key.Buckets) != 1 || key.Buckets[0].ID != b.ID {
		t.Fatalf("GetKey must list the granted bucket: %+v %v", key, err)
	}
	if _, err := c.DenyBucketKey(ctx, garage.DenyBucketKeyRequest{BucketID: b.ID, AccessKeyID: k.AccessKeyID, Permissions: garage.BucketKeyPerms{Write: true}}); err != nil {
		t.Fatal(err)
	}
	if p, _ := perms(); !p.Read || p.Write {
		t.Fatalf("deny write must keep read and drop write: %+v", p)
	}
	// Denying again is idempotent.
	if _, err := c.DenyBucketKey(ctx, garage.DenyBucketKeyRequest{BucketID: b.ID, AccessKeyID: k.AccessKeyID, Permissions: garage.BucketKeyPerms{Write: true}}); err != nil {
		t.Fatalf("repeating a deny: %v", err)
	}
}

// A non-empty bucket refuses deletion with 409 BucketNotEmpty, which the
// bucket and COSI finalizers map to "retry later" instead of failing.
func TestContract_DeleteNonEmptyBucketIsBucketNotEmpty(t *testing.T) {
	nd := readyNode(t)
	c := nd.client
	ctx := context.Background()
	b, err := c.CreateBucket(ctx, garage.CreateBucketRequest{GlobalAlias: "contract-nonempty"})
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.CreateKey(ctx, "contract-nonempty")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AllowBucketKey(ctx, garage.AllowBucketKeyRequest{BucketID: b.ID, AccessKeyID: k.AccessKeyID, Permissions: garage.BucketKeyPerms{Read: true, Write: true}}); err != nil {
		t.Fatal(err)
	}
	full, err := c.GetKey(ctx, garage.GetKeyRequest{ID: k.AccessKeyID, ShowSecretKey: true})
	if err != nil {
		t.Fatal(err)
	}
	s3PutObject(t, nd.s3Addr, full.AccessKeyID, full.SecretAccessKey, "contract-nonempty", "obj", []byte("hello"))

	err = c.DeleteBucket(ctx, b.ID)
	if !garage.IsBucketNotEmpty(err) {
		t.Fatalf("deleting a non-empty bucket: want 409 BucketNotEmpty, got %d: %v", apiStatus(err), err)
	}
	if _, err := c.GetBucket(ctx, garage.GetBucketRequest{ID: b.ID}); err != nil {
		t.Fatalf("a refused delete must keep the bucket: %v", err)
	}
	empty, err := c.CreateBucket(ctx, garage.CreateBucketRequest{GlobalAlias: "contract-empty"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteBucket(ctx, empty.ID); err != nil {
		t.Fatalf("deleting an empty bucket: %v", err)
	}
	if _, err := c.GetBucket(ctx, garage.GetBucketRequest{GlobalAlias: "contract-empty"}); !garage.IsNotFound(err) {
		t.Fatalf("a deleted bucket's alias must resolve to 404, got %d: %v", apiStatus(err), err)
	}
}

// A wrong admin token is a 403 (IsForbidden drives admin-token rotation and
// recovery), and SkipDeadNodes on a single-version layout is a 400 the
// cluster controller treats as "nothing to skip".
func TestContract_ForbiddenTokenAndSkipDeadNodesSingleVersion(t *testing.T) {
	nd := readyNode(t)
	ctx := context.Background()
	bad := garage.NewClient(nd.client.BaseURL(), "not-the-admin-token")
	if _, err := bad.GetClusterHealth(ctx); !garage.IsForbidden(err) {
		t.Fatalf("health with a wrong token: want 403, got %d: %v", apiStatus(err), err)
	}
	if _, err := bad.ListBuckets(ctx); !garage.IsForbidden(err) {
		t.Fatalf("ListBuckets with a wrong token: want 403, got %d: %v", apiStatus(err), err)
	}
	layout, err := nd.client.GetClusterLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = nd.client.ClusterLayoutSkipDeadNodes(ctx, garage.SkipDeadNodesRequest{Version: layout.Version})
	if !garage.IsBadRequest(err) {
		t.Fatalf("SkipDeadNodes with one layout version: want 400, got %d: %v", apiStatus(err), err)
	}
}
