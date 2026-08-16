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

package main

import (
	"flag"
	"testing"
)

func TestLeaderElectionFlagDefaultsAndUnsafeOverride(t *testing.T) {
	t.Parallel()
	flags := flag.NewFlagSet("leader-election-test", flag.ContinueOnError)
	var enabled, unsafeOverride bool
	bindLeaderElectionFlags(flags, &enabled, &unsafeOverride)
	if !enabled || unsafeOverride {
		t.Fatalf("unsafe flag defaults: leader-elect=%t unsafe-override=%t", enabled, unsafeOverride)
	}
	if err := flags.Parse([]string{"--leader-elect=false", "--unsafe-allow-no-leader-election"}); err != nil {
		t.Fatal(err)
	}
	if enabled || !unsafeOverride {
		t.Fatalf("explicit unsafe flags not parsed: leader-elect=%t unsafe-override=%t", enabled, unsafeOverride)
	}
}

func TestValidateLeaderElectionSafety(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name           string
		enabled        bool
		unsafeOverride bool
		wantError      bool
	}{
		{name: "safe default", enabled: true},
		{name: "explicit unsafe single-manager override", unsafeOverride: true},
		{name: "silent disable is rejected", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateLeaderElectionSafety(test.enabled, test.unsafeOverride)
			if (err != nil) != test.wantError {
				t.Fatalf("validateLeaderElectionSafety() error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}

// Not run in parallel: t.Setenv forbids it, since concurrent subtests would
// race on the shared process environment. t.Setenv also restores the prior
// value (or unsets it) automatically at the end of each subtest.
func TestClusterDomainDefault(t *testing.T) {
	// Go's testing package has no t.Unsetenv; t.Setenv("", "") is the
	// documented way to simulate "unset" for a test while still getting
	// automatic restoration.
	t.Run("falls back when unset", func(t *testing.T) {
		t.Setenv("CLUSTER_DOMAIN", "")
		if got := clusterDomainDefault(); got != defaultClusterDomain {
			t.Fatalf("clusterDomainDefault() = %q, want fallback %q", got, defaultClusterDomain)
		}
	})

	t.Run("uses the env var when set", func(t *testing.T) {
		t.Setenv("CLUSTER_DOMAIN", "kubernetes01.example.com")
		if got := clusterDomainDefault(); got != "kubernetes01.example.com" {
			t.Fatalf("clusterDomainDefault() = %q, want %q", got, "kubernetes01.example.com")
		}
	})
}
