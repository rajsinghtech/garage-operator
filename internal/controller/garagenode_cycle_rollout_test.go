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

package controller

import "testing"

func TestCyclePausedForNonActorStorageDrain(t *testing.T) {
	// Regression for #536: a storage-rollout handoff must NOT pause the whole
	// reconcile via this helper. Only a non-actor storage drain does.
	cases := []struct {
		name                          string
		drainActive, drainActorActive bool
		want                          bool
	}{
		{name: "idle", want: false},
		{name: "non-actor drain", drainActive: true, drainActorActive: false, want: true},
		{name: "drain actor", drainActive: true, drainActorActive: true, want: false},
		{name: "actor without active drain flag", drainActive: false, drainActorActive: true, want: false},
	}
	for _, tc := range cases {
		if got := cyclePausedForNonActorStorageDrain(tc.drainActive, tc.drainActorActive); got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}
