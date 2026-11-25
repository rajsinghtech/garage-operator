/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1beta1

import (
	"testing"

	"k8s.io/utils/ptr"

	"github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func TestS3AndK2VPublicEndpointRoundTrip(t *testing.T) {
	spoke := discoveryTestCluster("dxflrs/garage:v2.6.0", nil)
	spoke.Spec.S3API = &S3APIConfig{
		Region:                  "garage",
		RootDomain:              ".s3.example.com",
		PublicEndpoint:          "https://s3.example.com",
		PublicEndpointPathStyle: ptr.To(true),
	}
	spoke.Spec.K2VAPI = &K2VAPIConfig{PublicEndpoint: "https://k2v.example.com"}

	hub := &v1beta2.GarageCluster{}
	if err := spoke.ConvertTo(hub); err != nil {
		t.Fatal(err)
	}
	if hub.Spec.S3API == nil || hub.Spec.S3API.PublicEndpoint != "https://s3.example.com" ||
		hub.Spec.S3API.PublicEndpointPathStyle == nil || !*hub.Spec.S3API.PublicEndpointPathStyle ||
		hub.Spec.K2VAPI == nil || hub.Spec.K2VAPI.PublicEndpoint != "https://k2v.example.com" {
		t.Fatalf("convert to hub dropped public endpoint fields: s3=%+v k2v=%+v", hub.Spec.S3API, hub.Spec.K2VAPI)
	}

	back := &GarageCluster{}
	if err := back.ConvertFrom(hub); err != nil {
		t.Fatal(err)
	}
	if back.Spec.S3API == nil || back.Spec.S3API.PublicEndpoint != "https://s3.example.com" ||
		back.Spec.S3API.PublicEndpointPathStyle == nil || !*back.Spec.S3API.PublicEndpointPathStyle ||
		back.Spec.K2VAPI == nil || back.Spec.K2VAPI.PublicEndpoint != "https://k2v.example.com" {
		t.Fatalf("convert from hub dropped public endpoint fields: s3=%+v k2v=%+v", back.Spec.S3API, back.Spec.K2VAPI)
	}
}
