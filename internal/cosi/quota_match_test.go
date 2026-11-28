package cosi

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/rajsinghtech/garage-operator/internal/garage"
)

// Garage enforces a zero quota as a hard limit (no writes), so an existing
// Some(0) quota must not be mistaken for "no quota" when the class asks for
// none; otherwise the provisioner leaves the bucket unwritable.
func TestBucketQuotasMatchTreatsZeroAsAQuota(t *testing.T) {
	zero := uint64(0)
	size := resource.MustParse("1Mi")
	objects := int64(10)
	sizeBytes := uint64(size.Value())
	objCount := uint64(objects)
	cases := []struct {
		name     string
		existing *garage.BucketQuotas
		params   *BucketClassParameters
		want     bool
	}{
		{"no quota wanted, none set", nil, &BucketClassParameters{}, true},
		{"no quota wanted, null fields", &garage.BucketQuotas{}, &BucketClassParameters{}, true},
		{"no quota wanted, zero size set", &garage.BucketQuotas{MaxSize: &zero}, &BucketClassParameters{}, false},
		{"no quota wanted, zero objects set", &garage.BucketQuotas{MaxObjects: &zero}, &BucketClassParameters{}, false},
		{"wanted quotas match", &garage.BucketQuotas{MaxSize: &sizeBytes, MaxObjects: &objCount}, &BucketClassParameters{MaxSize: &size, MaxObjects: &objects}, true},
		{"wanted size missing", nil, &BucketClassParameters{MaxSize: &size}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bucketQuotasMatch(tc.existing, tc.params); got != tc.want {
				t.Fatalf("bucketQuotasMatch=%v, want %v", got, tc.want)
			}
		})
	}
}
