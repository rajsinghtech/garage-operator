package controller

import (
	"reflect"
	"testing"

	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Federated regions share the same cluster:<name>/<ns> ownership tag; the
// reaper must only consider gateway roles in its own zone, never another
// region's (#220).
func TestStaleGatewayRoles_ZoneScoped(t *testing.T) {
	ownTag := "cluster:gc/garage"
	tierTag := testTierGatewayTag
	roles := []garage.LayoutNodeRole{
		// local zone, not live/claimed -> stale, must be returned
		{ID: "local-dead", Zone: testZone, Tags: []string{ownTag, tierTag}},
		// remote region zone, same ownership+tier tags, not live/claimed ->
		// must be SKIPPED (belongs to another federated region)
		{ID: "remote-dead", Zone: "eu-west-1", Tags: []string{ownTag, tierTag}},
	}
	live := map[string]bool{}
	claimed := map[string]bool{}

	got := staleGatewayRoles(roles, testZone, "gc", "garage", live, claimed, nil, false)
	want := []string{"local-dead"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("staleGatewayRoles zone scoping: got %v, want %v", got, want)
	}
}

// Within the local zone, live and operator-claimed roles are preserved; only a
// genuinely orphaned role is reaped. A storage-tier role in the same zone (no
// tier:gateway tag) is never touched.
func TestStaleGatewayRoles_LivePreservedTierFiltered(t *testing.T) {
	ownTag := "cluster:gc/garage"
	tierTag := testTierGatewayTag
	roles := []garage.LayoutNodeRole{
		{ID: "gw-live", Zone: testZone, Tags: []string{ownTag, tierTag}},
		{ID: "gw-claimed", Zone: testZone, Tags: []string{ownTag, tierTag}},
		{ID: "gw-orphan", Zone: testZone, Tags: []string{ownTag, tierTag}},
		{ID: "storage-role", Zone: testZone, Tags: []string{ownTag, testTierStorageTag}},
	}
	live := map[string]bool{"gw-live": true}
	claimed := map[string]bool{"gw-claimed": true}

	got := staleGatewayRoles(roles, testZone, "gc", "garage", live, claimed, nil, false)
	want := []string{"gw-orphan"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("staleGatewayRoles: got %v, want %v", got, want)
	}
}

// #224 backstop: a federation re-import can strip a gateway role's tier:gateway /
// ownership tags, leaving only a remote-name tag, which makes the tag-based path miss
// it. With hardenUntagged (set for unified Auto clusters) a local-zone, capacity:null,
// unclaimed, SUSTAINED-down role is reaped by shape even without the tier tag — but the
// gate must not over-reap (different zone, claimed/live, storage-shaped, not-yet-sustained
// down, or hardenUntagged off).
func TestStaleGatewayRoles_HardenUntagged(t *testing.T) {
	cap := uint64(1 << 40)
	const strayTag = "someremote" // a federation re-import left only this tag (no tier/ownership)
	const orphanID = "tagless-orphan"
	roles := []garage.LayoutNodeRole{
		// the #224 orphan: local zone, capacity:null, only a stray remote-name tag, sustained down
		{ID: orphanID, Zone: testZone, Tags: []string{strayTag}, Capacity: nil},
		// down but NOT sustained (transient blip / briefly-down federated peer): must be preserved
		{ID: "tagless-blip", Zone: testZone, Tags: []string{strayTag}, Capacity: nil},
		// live: must be preserved even when tagless+shaped
		{ID: "tagless-live", Zone: testZone, Tags: []string{strayTag}, Capacity: nil},
		// claimed by a live GarageNode (mid-restart): must be preserved
		{ID: "tagless-claimed", Zone: testZone, Tags: []string{strayTag}, Capacity: nil},
		// different zone: zone gate must skip it
		{ID: "tagless-remote", Zone: "eu-west-1", Tags: []string{strayTag}, Capacity: nil},
		// storage-shaped (capacity non-nil): not gateway-shaped, never reaped by the backstop
		{ID: "tagless-storage", Zone: testZone, Tags: []string{strayTag}, Capacity: &cap},
	}
	live := map[string]bool{"tagless-live": true}
	claimed := map[string]bool{"tagless-claimed": true}
	// Only sustained-down IDs are eligible for the untagged backstop. tagless-blip is
	// deliberately absent (down but within the dwell window).
	sustainedDown := map[string]bool{orphanID: true, "tagless-remote": true, "tagless-storage": true}

	// hardenUntagged=true (unified Auto cluster): only the genuine sustained-down orphan is reaped.
	got := staleGatewayRoles(roles, testZone, "gc", "garage", live, claimed, sustainedDown, true)
	want := []string{orphanID}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("staleGatewayRoles hardenUntagged=true: got %v, want %v", got, want)
	}

	// hardenUntagged=false (edge gateway / Manual): tagless roles are never reaped.
	if got := staleGatewayRoles(roles, testZone, "gc", "garage", live, claimed, sustainedDown, false); len(got) != 0 {
		t.Fatalf("staleGatewayRoles hardenUntagged=false: expected no reaping, got %v", got)
	}
}
