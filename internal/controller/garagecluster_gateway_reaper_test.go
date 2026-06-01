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

	got := staleGatewayRoles(roles, testZone, "gc", "garage", live, claimed)
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

	got := staleGatewayRoles(roles, testZone, "gc", "garage", live, claimed)
	want := []string{"gw-orphan"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("staleGatewayRoles: got %v, want %v", got, want)
	}
}
