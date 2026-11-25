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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"
)

// crdSizeBudgetBytes caps the compact JSON size of every generated CRD.
// etcd rejects requests over 1.5 MiB by default (--max-request-bytes), and the
// stored CRD also carries status and metadata. Keeping each CRD under 1 MiB
// leaves headroom; the GarageCluster CRD serves two full schemas and was
// about 655 KB when this guard was added.
const crdSizeBudgetBytes = 1 << 20

func TestGeneratedCRDsStayWithinSizeBudget(t *testing.T) {
	root := filepath.Join("..", "..", "config", "crd", "bases")
	paths, err := filepath.Glob(filepath.Join(root, "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no CRDs found under %s", root)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var crd map[string]any
		if err := yaml.Unmarshal(raw, &crd); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		compact, err := json.Marshal(crd)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if len(compact) > crdSizeBudgetBytes {
			t.Errorf("%s is %d bytes as JSON, over the %d-byte budget; trim schema (descriptions, embedded core types) before etcd's 1.5 MiB request limit is reached",
				filepath.Base(path), len(compact), crdSizeBudgetBytes)
		}
	}
}
