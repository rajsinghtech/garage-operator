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

package cosi

import (
	"fmt"
	"strconv"

	"k8s.io/apimachinery/pkg/api/resource"
)

// BucketClassParameters holds parsed BucketClass parameters
type BucketClassParameters struct {
	ClusterRef       string
	ClusterNamespace string
	MaxSize          *resource.Quantity
	MaxObjects       *int64
	WebsiteEnabled   bool
}

// BucketAccessClassParameters holds parsed BucketAccessClass parameters
type BucketAccessClassParameters struct {
	ClusterRef       string
	ClusterNamespace string
}

// ParseBucketClassParameters parses BucketClass parameters
func ParseBucketClassParameters(params map[string]string, defaultNamespace string) (*BucketClassParameters, error) {
	clusterRef, ok := params["clusterRef"]
	if !ok || clusterRef == "" {
		return nil, fmt.Errorf("required parameter 'clusterRef' not specified")
	}

	clusterNS := params["clusterNamespace"]
	if clusterNS == "" {
		clusterNS = defaultNamespace
	}

	p := &BucketClassParameters{
		ClusterRef:       clusterRef,
		ClusterNamespace: clusterNS,
	}

	if maxSize, ok := params["maxSize"]; ok {
		q, err := resource.ParseQuantity(maxSize)
		if err != nil {
			return nil, fmt.Errorf("invalid maxSize: %w", err)
		}
		p.MaxSize = &q
	}

	if maxObjects, ok := params["maxObjects"]; ok {
		n, err := strconv.ParseInt(maxObjects, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid maxObjects: %w", err)
		}
		p.MaxObjects = &n
	}

	if websiteEnabled, ok := params["websiteEnabled"]; ok {
		p.WebsiteEnabled = websiteEnabled == "true"
	}

	return p, nil
}

// ParseBucketAccessClassParameters parses BucketAccessClass parameters
func ParseBucketAccessClassParameters(params map[string]string, defaultNamespace string) (*BucketAccessClassParameters, error) {
	clusterRef, ok := params["clusterRef"]
	if !ok || clusterRef == "" {
		return nil, fmt.Errorf("required parameter 'clusterRef' not specified")
	}

	clusterNS := params["clusterNamespace"]
	if clusterNS == "" {
		clusterNS = defaultNamespace
	}

	return &BucketAccessClassParameters{
		ClusterRef:       clusterRef,
		ClusterNamespace: clusterNS,
	}, nil
}
