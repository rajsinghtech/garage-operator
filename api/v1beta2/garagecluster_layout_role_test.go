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

package v1beta2

import (
	"context"
	"strings"
	"testing"
)

func layoutRoleCluster(role LayoutSiteRole) *GarageCluster {
	cluster := scaleFreezeCluster(3)
	cluster.Status.Conditions = nil
	if role != "" {
		cluster.Spec.LayoutManagement = &LayoutManagementConfig{SiteRole: role}
	}
	if role == LayoutSiteRoleFollower {
		cluster.Spec.RemoteClusters = []RemoteClusterConfig{{Name: "writer", Zone: "us-west"}}
	}
	return cluster
}

func TestEffectiveLayoutSiteRole(t *testing.T) {
	tests := []struct {
		name     string
		cluster  *GarageCluster
		want     LayoutSiteRole
		follower bool
	}{
		{"nil cluster", nil, LayoutSiteRoleWriter, false},
		{"no layoutManagement", &GarageCluster{}, LayoutSiteRoleWriter, false},
		{"layoutManagement without siteRole", &GarageCluster{Spec: GarageClusterSpec{LayoutManagement: &LayoutManagementConfig{}}}, LayoutSiteRoleWriter, false},
		{"explicit writer", layoutRoleCluster(LayoutSiteRoleWriter), LayoutSiteRoleWriter, false},
		{"explicit follower", layoutRoleCluster(LayoutSiteRoleFollower), LayoutSiteRoleFollower, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cluster.EffectiveLayoutSiteRole(); got != tt.want {
				t.Fatalf("EffectiveLayoutSiteRole = %q, want %q", got, tt.want)
			}
			if got := tt.cluster.IsLayoutFollower(); got != tt.follower {
				t.Fatalf("IsLayoutFollower = %v, want %v", got, tt.follower)
			}
		})
	}
}

func TestValidateUpdate_DemotionRejectedDuringLayoutTransaction(t *testing.T) {
	validator := &GarageClusterValidator{}
	tests := []struct {
		name    string
		mutate  func(*GarageCluster)
		wantErr string // empty: demotion must be allowed
	}{
		{"idle writer", func(*GarageCluster) {}, ""},
		{"storage drain", func(c *GarageCluster) {
			c.Status.StorageDrain = &StorageDrainStatus{TransactionID: "tx-1"}
		}, "status.storageDrain"},
		{"storage rollout", func(c *GarageCluster) {
			c.Status.StorageRollout = &StorageRolloutStatus{GarageNodeName: "node-1"}
		}, "status.storageRollout"},
		{"purge annotation", func(c *GarageCluster) {
			c.Annotations = map[string]string{purgeClusterLayoutAnnotation: "true"}
		}, "replication-factor migration"},
		{"factor migration in flight", func(c *GarageCluster) {
			c.Status.FactorMigration = &FactorMigrationStatus{Phase: "Purging"}
		}, "status.factorMigration in phase Purging"},
		{"factor migration completed", func(c *GarageCluster) {
			c.Status.FactorMigration = &FactorMigrationStatus{Phase: factorMigrationPhaseCompleted}
		}, ""},
		{"factor migration failed", func(c *GarageCluster) {
			c.Status.FactorMigration = &FactorMigrationStatus{Phase: factorMigrationPhaseFailed}
		}, ""},
		{"factor migration without phase", func(c *GarageCluster) {
			c.Status.FactorMigration = &FactorMigrationStatus{}
		}, ""},
	}
	for _, role := range []LayoutSiteRole{LayoutSiteRoleWriter, ""} {
		for _, tt := range tests {
			t.Run(string(role)+"/"+tt.name, func(t *testing.T) {
				old := layoutRoleCluster(role)
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
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) ||
					!strings.Contains(err.Error(), "Writer to Follower") {
					t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
				}
			})
		}
	}
}

func TestValidateUpdate_PromotionWarnsButIsNeverBlocked(t *testing.T) {
	validator := &GarageClusterValidator{}
	old := layoutRoleCluster(LayoutSiteRoleFollower)
	// The role change itself is never blocked: failover has to work when the
	// previous writer is gone. (The existing storage-drain spec freeze is
	// unrelated and still applies to any spec edit.)
	newer := old.DeepCopy()
	newer.Generation++
	newer.Spec.LayoutManagement = &LayoutManagementConfig{SiteRole: LayoutSiteRoleWriter}

	warnings, err := validator.ValidateUpdate(context.Background(), old, newer)
	if err != nil {
		t.Fatalf("promotion must not be rejected: %v", err)
	}
	found := false
	for _, w := range warnings {
		found = found || strings.Contains(w, "promoting this site to layout Writer")
	}
	if !found {
		t.Fatalf("promotion warning missing: %v", warnings)
	}
}

func TestValidateUpdate_ReplicationChangeOnFollowerWarns(t *testing.T) {
	validator := &GarageClusterValidator{}
	old := layoutRoleCluster(LayoutSiteRoleFollower)
	newer := old.DeepCopy()
	newer.Generation++
	newer.Spec.Replication = &ReplicationConfig{Factor: 1, ZoneRedundancyMode: "Maximum"}

	warnings, err := validator.ValidateUpdate(context.Background(), old, newer)
	if err != nil {
		t.Fatalf("a replication change on a follower must warn, not reject: %v", err)
	}
	found := false
	for _, w := range warnings {
		found = found || (strings.Contains(w, "ReplicationChange") && strings.Contains(w, "Writer site"))
	}
	if !found {
		t.Fatalf("replication warning missing: %v", warnings)
	}

	unchanged := old.DeepCopy()
	unchanged.Generation++
	warnings, err = validator.ValidateUpdate(context.Background(), old, unchanged)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "ReplicationChange") {
			t.Fatalf("no replication change must not warn: %v", warnings)
		}
	}

	writerOld := layoutRoleCluster(LayoutSiteRoleWriter)
	writerNew := writerOld.DeepCopy()
	writerNew.Generation++
	writerNew.Spec.Replication = &ReplicationConfig{Factor: 1, ZoneRedundancyMode: "Maximum"}
	warnings, _ = validator.ValidateUpdate(context.Background(), writerOld, writerNew)
	for _, w := range warnings {
		if strings.Contains(w, "ReplicationChange") {
			t.Fatalf("writer must not get the follower replication warning: %v", warnings)
		}
	}
}

func TestValidateLayoutManagementSiteRole(t *testing.T) {
	validator := &GarageClusterValidator{}
	tests := []struct {
		name    string
		mutate  func(*GarageCluster)
		wantErr string
	}{
		{"writer without remoteClusters", func(c *GarageCluster) {
			c.Spec.LayoutManagement = &LayoutManagementConfig{SiteRole: LayoutSiteRoleWriter}
		}, ""},
		{"follower with remoteClusters", func(c *GarageCluster) {
			c.Spec.LayoutManagement = &LayoutManagementConfig{SiteRole: LayoutSiteRoleFollower}
			c.Spec.RemoteClusters = []RemoteClusterConfig{{Name: "writer", Zone: "us-west"}}
		}, ""},
		{"follower without remoteClusters", func(c *GarageCluster) {
			c.Spec.LayoutManagement = &LayoutManagementConfig{SiteRole: LayoutSiteRoleFollower}
		}, "remoteClusters"},
		{"follower with connectTo", func(c *GarageCluster) {
			c.Spec.LayoutManagement = &LayoutManagementConfig{SiteRole: LayoutSiteRoleFollower}
			c.Spec.RemoteClusters = []RemoteClusterConfig{{Name: "writer", Zone: "us-west"}}
			c.Spec.ConnectTo = &ConnectToConfig{ClusterRef: &ClusterReference{Name: "other"}}
		}, "connectTo"},
		{"unknown role", func(c *GarageCluster) {
			c.Spec.LayoutManagement = &LayoutManagementConfig{SiteRole: "Leader"}
		}, "siteRole"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cluster := layoutRoleCluster("")
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
