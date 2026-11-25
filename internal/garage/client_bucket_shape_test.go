/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package garage

import (
	"encoding/json"
	"testing"
)

// GetBucketInfo (v2.3.0+) nests routingRules inside websiteConfig
// (GetBucketInfoWebsiteResponse in src/api/admin/api.rs).
func TestBucketWebsiteConfigDecodesNestedRoutingRules(t *testing.T) {
	raw := `{"id":"b1","created":"2026-01-01T00:00:00Z","globalAliases":["site"],
	"websiteAccess":true,
	"websiteConfig":{"indexDocument":"index.html","errorDocument":"404.html",
	 "routingRules":[{"condition":{"prefix":"old/"},"redirect":{"replaceKeyPrefixWith":"new/"}}]},
	"keys":[],"objects":0,"bytes":0,"unfinishedUploads":0,
	"unfinishedMultipartUploads":0,"unfinishedMultipartUploadParts":0,
	"unfinishedMultipartUploadBytes":0,"quotas":{}}`
	var b Bucket
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		t.Fatal(err)
	}
	if b.WebsiteConfig == nil || b.WebsiteConfig.IndexDocument != "index.html" {
		t.Fatalf("websiteConfig = %+v", b.WebsiteConfig)
	}
	if len(b.WebsiteConfig.RoutingRules) != 1 {
		t.Fatalf("routingRules = %d, want 1", len(b.WebsiteConfig.RoutingRules))
	}
}

// Leaving routingRules out of UpdateBucket keeps the bucket's existing rules,
// so the request body must never carry the key.
func TestUpdateBucketWebsiteAccessOmitsRoutingRules(t *testing.T) {
	out, err := json.Marshal(UpdateBucketRequestBody{WebsiteAccess: &UpdateBucketWebsiteAccess{Enabled: true, IndexDocument: "index.html"}})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["websiteAccess"]["routingRules"]; ok {
		t.Fatalf("UpdateBucket body carries routingRules: %s", out)
	}
}
