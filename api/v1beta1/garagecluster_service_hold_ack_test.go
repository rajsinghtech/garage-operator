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
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// #603: the v1beta1 webhook enforces the same acknowledgement contract.
func TestNodeLocalServiceHoldAcknowledgeUnverifiedRequiresHoldAndNodeID(t *testing.T) {
	cluster := &GarageCluster{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		AnnotationNodeLocalOutOfServiceAcknowledgeUnverified: strings.Repeat("a", 64),
	}}}
	if err := cluster.validateNodeLocalServiceHoldAnnotations(); err == nil || !strings.Contains(err.Error(), "requires") {
		t.Fatalf("acknowledgement without a hold accepted: %v", err)
	}
	cluster.Annotations[AnnotationNodeLocalOutOfService] = "pool/worker-a"
	cluster.Annotations[AnnotationNodeLocalOutOfServiceAcknowledgeUnverified] = "worker-a"
	if err := cluster.validateNodeLocalServiceHoldAnnotations(); err == nil || !strings.Contains(err.Error(), "64-hex") {
		t.Fatalf("malformed acknowledgement accepted: %v", err)
	}
}
