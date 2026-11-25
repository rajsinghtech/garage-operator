/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta2

import (
	"strings"
	"testing"

	"k8s.io/utils/ptr"
)

func TestPublicEndpointAdmission(t *testing.T) {
	for _, tc := range []struct {
		name     string
		image    string
		mutate   func(*GarageCluster)
		wantErr  string
		wantWarn string
	}{
		{
			name:  "valid urls on v2.5+",
			image: "dxflrs/garage:v2.5.0",
			mutate: func(c *GarageCluster) {
				c.Spec.S3API = &S3APIConfig{Region: "garage", PublicEndpoint: "https://s3.example.com", PublicEndpointPathStyle: ptr.To(true)}
				c.Spec.K2VAPI = &K2VAPIConfig{PublicEndpoint: "https://k2v.example.com"}
			},
		},
		{
			name:  "older image warns and is not rejected",
			image: "dxflrs/garage:v2.4.1",
			mutate: func(c *GarageCluster) {
				c.Spec.S3API = &S3APIConfig{Region: "garage", PublicEndpoint: "https://s3.example.com"}
			},
			wantWarn: "v2.5.0",
		},
		{
			name:  "digest-only is not guessed at",
			image: "dxflrs/garage@sha256:4b5a318fc9fe2fbec5d3af590eeafe05d83492e6411266fa0b9e215c20264013",
			mutate: func(c *GarageCluster) {
				c.Spec.S3API = &S3APIConfig{Region: "garage", PublicEndpoint: "https://s3.example.com"}
			},
		},
		{
			name:  "invalid s3 url rejected",
			image: "dxflrs/garage:v2.6.0",
			mutate: func(c *GarageCluster) {
				c.Spec.S3API = &S3APIConfig{Region: "garage", PublicEndpoint: "not-a-url"}
			},
			wantErr: "spec.s3Api.publicEndpoint",
		},
		{
			name:  "invalid k2v url rejected",
			image: "dxflrs/garage:v2.6.0",
			mutate: func(c *GarageCluster) {
				c.Spec.K2VAPI = &K2VAPIConfig{PublicEndpoint: "k2v.example.com"}
			},
			wantErr: "spec.k2vApi.publicEndpoint",
		},
		{
			name:  "path style false without rootDomain warns",
			image: "dxflrs/garage:v2.5.0",
			mutate: func(c *GarageCluster) {
				c.Spec.S3API = &S3APIConfig{Region: "garage", PublicEndpointPathStyle: ptr.To(false)}
			},
			wantWarn: "rootDomain",
		},
		{
			name:  "empty publicEndpoint is unset",
			image: "dxflrs/garage:v2.4.1",
			mutate: func(c *GarageCluster) {
				c.Spec.S3API = &S3APIConfig{Region: "garage", PublicEndpoint: "  "}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cluster := discoveryTestCluster(tc.image, nil)
			tc.mutate(cluster)
			warnings, err := cluster.validateGarageCluster()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if tc.wantWarn != "" {
				if warningsContaining(warnings, tc.wantWarn) == 0 {
					t.Fatalf("warnings = %v, want substring %q", warnings, tc.wantWarn)
				}
			} else if warningsContaining(warnings, "publicEndpoint") != 0 || warningsContaining(warnings, "v2.5.0") != 0 {
				t.Fatalf("unexpected public-endpoint warning: %v", warnings)
			}
		})
	}
}
