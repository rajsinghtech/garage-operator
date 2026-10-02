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

package v1beta1

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func layoutRoleSpoke(role LayoutSiteRole) *GarageCluster {
	cluster := &GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "layout-role", Namespace: testNS, Generation: 2},
		Spec: GarageClusterSpec{
			Replicas:    3,
			Zone:        testZone,
			Replication: &ReplicationConfig{Factor: 3},
			Storage: StorageConfig{
				Metadata: &VolumeConfig{Size: ptrQuantity(resource.MustParse(test10Gi))},
				Data:     &VolumeConfig{Size: ptrQuantity(resource.MustParse("100Gi"))},
			},
		},
	}
	if role != "" {
		cluster.Spec.LayoutManagement = &LayoutManagementConfig{SiteRole: role}
	}
	if role == LayoutSiteRoleFollower {
		cluster.Spec.RemoteClusters = []RemoteClusterConfig{{Name: "writer", Zone: "us-west"}}
	}
	return cluster
}

func TestConvert_LayoutSiteRoleRoundTrip(t *testing.T) {
	for _, role := range []LayoutSiteRole{LayoutSiteRoleWriter, LayoutSiteRoleFollower} {
		t.Run(string(role), func(t *testing.T) {
			src := layoutRoleSpoke(role)
			src.Status.LayoutWriter = &LayoutWriterStatus{Role: role}

			up := &v1beta2.GarageCluster{}
			if err := src.ConvertTo(up); err != nil {
				t.Fatalf("ConvertTo: %v", err)
			}
			if up.Spec.LayoutManagement == nil || string(up.Spec.LayoutManagement.SiteRole) != string(role) {
				t.Fatalf("hub layoutManagement = %+v, want siteRole %q", up.Spec.LayoutManagement, role)
			}
			if up.Status.LayoutWriter == nil || string(up.Status.LayoutWriter.Role) != string(role) {
				t.Fatalf("hub status.layoutWriter = %+v, want role %q", up.Status.LayoutWriter, role)
			}

			down := &GarageCluster{}
			if err := down.ConvertFrom(up); err != nil {
				t.Fatalf("ConvertFrom: %v", err)
			}
			if down.Spec.LayoutManagement == nil || down.Spec.LayoutManagement.SiteRole != role {
				t.Fatalf("round-trip layoutManagement = %+v, want siteRole %q", down.Spec.LayoutManagement, role)
			}
			if down.Status.LayoutWriter == nil || down.Status.LayoutWriter.Role != role {
				t.Fatalf("round-trip status.layoutWriter = %+v, want role %q", down.Status.LayoutWriter, role)
			}
			if got := down.Annotations[v1beta2AnnotationGatewayTierPresent]; got != "" {
				t.Fatalf("siteRole must not be reported as v1beta2-only, got annotation %q", got)
			}
		})
	}
}

// siteRole has no default anywhere: an object that never set it must not gain
// a Writer value through conversion in either direction.
func TestConvert_LayoutSiteRoleAbsentStaysAbsent(t *testing.T) {
	for _, withLayoutManagement := range []bool{false, true} {
		src := layoutRoleSpoke("")
		if withLayoutManagement {
			src.Spec.LayoutManagement = &LayoutManagementConfig{AutoApply: true}
		}
		up := &v1beta2.GarageCluster{}
		if err := src.ConvertTo(up); err != nil {
			t.Fatalf("ConvertTo: %v", err)
		}
		if up.Spec.LayoutManagement != nil && up.Spec.LayoutManagement.SiteRole != "" {
			t.Fatalf("hub gained siteRole %q", up.Spec.LayoutManagement.SiteRole)
		}
		if up.Status.LayoutWriter != nil {
			t.Fatalf("hub gained status.layoutWriter %+v", up.Status.LayoutWriter)
		}
		down := &GarageCluster{}
		if err := down.ConvertFrom(up); err != nil {
			t.Fatalf("ConvertFrom: %v", err)
		}
		if down.Spec.LayoutManagement != nil && down.Spec.LayoutManagement.SiteRole != "" {
			t.Fatalf("spoke gained siteRole %q", down.Spec.LayoutManagement.SiteRole)
		}
		if down.Status.LayoutWriter != nil {
			t.Fatalf("spoke gained status.layoutWriter %+v", down.Status.LayoutWriter)
		}
		raw, err := json.Marshal(down.Spec)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "siteRole") {
			t.Fatalf("absent siteRole serialized: %s", raw)
		}
	}
}

// The hub is the storage version: a v1beta2 object written with siteRole must
// reach a v1beta1 reader intact, including next to other layoutManagement fields.
func TestConvert_LayoutSiteRoleFromHubKeepsSiblingFields(t *testing.T) {
	hub := &v1beta2.GarageCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "hub", Namespace: testNS},
		Spec: v1beta2.GarageClusterSpec{
			Zone:    testZone,
			Storage: &v1beta2.StorageSpec{Replicas: 3},
			LayoutManagement: &v1beta2.LayoutManagementConfig{
				AutoApply: true, SiteRole: v1beta2.LayoutSiteRoleFollower,
			},
			RemoteClusters: []v1beta2.RemoteClusterConfig{{Name: "writer", Zone: "us-west"}},
		},
	}
	down := &GarageCluster{}
	if err := down.ConvertFrom(hub); err != nil {
		t.Fatalf("ConvertFrom: %v", err)
	}
	if lm := down.Spec.LayoutManagement; lm == nil || lm.SiteRole != LayoutSiteRoleFollower || !lm.AutoApply {
		t.Fatalf("layoutManagement = %+v", lm)
	}
	back := &v1beta2.GarageCluster{}
	if err := down.ConvertTo(back); err != nil {
		t.Fatalf("ConvertTo: %v", err)
	}
	if lm := back.Spec.LayoutManagement; lm == nil || lm.SiteRole != v1beta2.LayoutSiteRoleFollower || !lm.AutoApply {
		t.Fatalf("round-trip layoutManagement = %+v", lm)
	}
}

func TestV1Beta1ValidateUpdate_DemotionRejectedDuringLayoutTransaction(t *testing.T) {
	validator := &GarageClusterValidator{}
	tests := []struct {
		name    string
		mutate  func(*GarageCluster)
		wantErr string
	}{
		{"idle writer", func(*GarageCluster) {}, ""},
		{"storage drain", func(c *GarageCluster) {
			c.Status.StorageDrain = &StorageDrainStatus{TransactionID: "tx-1"}
		}, "status.storageDrain"},
		{"storage rollout", func(c *GarageCluster) {
			c.Status.StorageRollout = &StorageRolloutStatus{GarageNodeName: "node-1"}
		}, "status.storageRollout"},
		{"purge annotation", func(c *GarageCluster) {
			c.Annotations = map[string]string{AnnotationPurgeClusterLayout: "factor=1"}
		}, "replication-factor migration"},
		{"factor migration in flight", func(c *GarageCluster) {
			c.Status.FactorMigration = &FactorMigrationStatus{Phase: "Purging"}
		}, "status.factorMigration in phase Purging"},
		{"factor migration completed", func(c *GarageCluster) {
			c.Status.FactorMigration = &FactorMigrationStatus{Phase: "Completed"}
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := layoutRoleSpoke(LayoutSiteRoleWriter)
			tt.mutate(old)
			newer := old.DeepCopy()
			newer.Generation++
			newer.Spec.LayoutManagement = &LayoutManagementConfig{SiteRole: LayoutSiteRoleFollower}
			newer.Spec.RemoteClusters = []RemoteClusterConfig{{Name: "writer", Zone: "us-west"}}
			_, err := validator.ValidateUpdate(context.Background(), old, newer)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("demotion must be allowed: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestV1Beta1ValidateLayoutManagementSiteRole(t *testing.T) {
	validator := &GarageClusterValidator{}
	tests := []struct {
		name    string
		mutate  func(*GarageCluster)
		wantErr string
	}{
		{"follower with remoteClusters", func(*GarageCluster) {}, ""},
		{"follower without remoteClusters", func(c *GarageCluster) { c.Spec.RemoteClusters = nil }, "remoteClusters"},
		{"follower with connectTo", func(c *GarageCluster) {
			c.Spec.ConnectTo = &ConnectToConfig{ClusterRef: &ClusterReference{Name: "other"}}
		}, "connectTo"},
		{"unknown role", func(c *GarageCluster) {
			c.Spec.LayoutManagement.SiteRole = "Leader"
		}, "siteRole"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cluster := layoutRoleSpoke(LayoutSiteRoleFollower)
			tt.mutate(cluster)
			_, err := validator.ValidateCreate(context.Background(), cluster)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}
