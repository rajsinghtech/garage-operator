package v1beta1

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A zero quota blocks every write in Garage. Admission must say so, because
// status and metrics report a zero limit the same way as "unlimited".
func TestGarageBucketZeroQuotaWarns(t *testing.T) {
	zeroSize := resource.MustParse("0")
	zeroObjects := int64(0)
	bucket := &GarageBucket{
		ObjectMeta: metav1.ObjectMeta{Name: "quota-bucket", Namespace: "default"},
		Spec: GarageBucketSpec{
			ClusterRef: ClusterReference{Name: "garage"},
			Quotas:     &BucketQuotas{MaxSize: &zeroSize, MaxObjects: &zeroObjects},
		},
	}
	warnings, err := (&GarageBucketValidator{}).ValidateCreate(context.Background(), bucket)
	if err != nil {
		t.Fatalf("ValidateCreate: %v", err)
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"spec.quotas.maxSize is 0", "spec.quotas.maxObjects is 0"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("warnings=%q, want one containing %q", warnings, want)
		}
	}

	size := resource.MustParse("1Gi")
	bucket.Spec.Quotas = &BucketQuotas{MaxSize: &size}
	warnings, err = (&GarageBucketValidator{}).ValidateCreate(context.Background(), bucket)
	if err != nil {
		t.Fatalf("ValidateCreate: %v", err)
	}
	if strings.Contains(strings.Join(warnings, "\n"), "quotas") {
		t.Fatalf("warnings=%q, want no quota warning for a non-zero quota", warnings)
	}
}
