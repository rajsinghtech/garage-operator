/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	garagev1beta2 "github.com/rajsinghtech/garage-operator/api/v1beta2"
)

func TestGenerateGarageConfigPublicEndpoints(t *testing.T) {
	pathStyle := ptr.To(true)
	base := func(image string) *garagev1beta2.GarageCluster {
		return &garagev1beta2.GarageCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "ep", Namespace: "ns"},
			Spec: garagev1beta2.GarageClusterSpec{
				Image:   image,
				Storage: &garagev1beta2.StorageSpec{Replicas: 1},
				S3API: &garagev1beta2.S3APIConfig{
					Region:                  "garage",
					RootDomain:              ".s3.example.com",
					PublicEndpoint:          "https://s3.example.com",
					PublicEndpointPathStyle: pathStyle,
				},
				K2VAPI: &garagev1beta2.K2VAPIConfig{
					PublicEndpoint: "https://k2v.example.com",
				},
			},
		}
	}

	t.Run("rendered on v2.5+", func(t *testing.T) {
		cfg := generateGarageConfig(base("dxflrs/garage:v2.5.0"), &configContext{})
		for _, want := range []string{
			`public_endpoint = "https://s3.example.com"`,
			`public_endpoint_path_style = true`,
			`public_endpoint = "https://k2v.example.com"`,
		} {
			if !strings.Contains(cfg, want) {
				t.Fatalf("config missing %q:\n%s", want, cfg)
			}
		}
		s3 := section(cfg, "[s3_api]")
		k2v := section(cfg, "[k2v_api]")
		if !strings.Contains(s3, `public_endpoint = "https://s3.example.com"`) || strings.Contains(k2v, "s3.example.com") {
			t.Fatalf("s3 endpoint landed outside [s3_api]: s3=%q k2v=%q", s3, k2v)
		}
		if !strings.Contains(k2v, `public_endpoint = "https://k2v.example.com"`) || strings.Contains(s3, "k2v.example.com") {
			t.Fatalf("k2v endpoint landed outside [k2v_api]: s3=%q k2v=%q", s3, k2v)
		}
	})

	t.Run("omitted on older tagged images", func(t *testing.T) {
		cfg := generateGarageConfig(base("dxflrs/garage:v2.4.1"), &configContext{})
		if strings.Contains(cfg, "public_endpoint") {
			t.Fatalf("older image must not render public_endpoint keys:\n%s", cfg)
		}
	})

	t.Run("default image (v2.6) renders", func(t *testing.T) {
		cluster := base("")
		cfg := generateGarageConfig(cluster, &configContext{})
		if !strings.Contains(cfg, `public_endpoint = "https://s3.example.com"`) {
			t.Fatalf("empty image should use the v2.6 default and render:\n%s", cfg)
		}
	})

	t.Run("unset fields stay omitted", func(t *testing.T) {
		cluster := base("dxflrs/garage:v2.6.0")
		cluster.Spec.S3API.PublicEndpoint = ""
		cluster.Spec.S3API.PublicEndpointPathStyle = nil
		cluster.Spec.K2VAPI.PublicEndpoint = ""
		cfg := generateGarageConfig(cluster, &configContext{})
		if strings.Contains(cfg, "public_endpoint") {
			t.Fatalf("unset fields must not appear:\n%s", cfg)
		}
	})
}

func section(cfg, header string) string {
	i := strings.Index(cfg, header)
	if i < 0 {
		return ""
	}
	rest := cfg[i+len(header):]
	if j := strings.Index(rest, "\n["); j >= 0 {
		return rest[:j]
	}
	return rest
}
