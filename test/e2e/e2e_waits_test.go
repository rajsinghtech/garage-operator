//go:build e2e
// +build e2e

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

package e2e

import "testing"

func TestE2EWebhookServiceHasHTTPS(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want bool
	}{
		{
			name: "webhook port",
			json: `{"spec":{"ports":[{"port":443}]}}`,
			want: true,
		},
		{
			name: "metrics only",
			json: `{"spec":{"ports":[{"port":8443}]}}`,
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e2EWebhookServiceHasHTTPS(tc.json)
			if err != nil {
				t.Fatalf("parse Service: %v", err)
			}
			if got != tc.want {
				t.Fatalf("has HTTPS = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestE2EReadyWebhookAddresses(t *testing.T) {
	output := `{
  "items": [
    {"endpoints": [
      {"addresses":["10.0.0.3"],"conditions":{"ready":false}},
      {"addresses":["10.0.0.2"],"conditions":{"ready":true,"serving":true}},
      {"addresses":["10.0.0.4"],"conditions":{"ready":true,"terminating":true}}
    ]},
    {"endpoints": [
      {"addresses":["10.0.0.1"],"conditions":{"ready":true}}
    ]}
  ]
}`
	addresses, err := e2EReadyWebhookAddresses(output)
	if err != nil {
		t.Fatalf("parse EndpointSlices: %v", err)
	}
	want := []string{"10.0.0.1", "10.0.0.2"}
	if len(addresses) != len(want) {
		t.Fatalf("ready addresses = %v, want %v", addresses, want)
	}
	for i := range want {
		if addresses[i] != want[i] {
			t.Fatalf("ready addresses = %v, want %v", addresses, want)
		}
	}
}

func TestE2ENamespacePhase(t *testing.T) {
	phase, err := e2eNamespacePhase(`Warning: deprecated output
{"status":{"phase":"Terminating"}}`)
	if err != nil {
		t.Fatalf("parse namespace: %v", err)
	}
	if phase != "Terminating" {
		t.Fatalf("phase = %q, want Terminating", phase)
	}
}
