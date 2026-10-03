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
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	importLegacyID     = "GK0123456789abcdef01234567"
	importLegacySecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func importKeyForTest(importKey *ImportKeyConfig) *GarageKey {
	return &GarageKey{
		ObjectMeta: metav1.ObjectMeta{Name: "imported", Namespace: testSourceNS},
		Spec: GarageKeySpec{
			ClusterRef: ClusterReference{Name: testCluster},
			ImportKey:  importKey,
		},
	}
}

func validateImportKeyForTest(t *testing.T, importKey *ImportKeyConfig) ([]string, error) {
	t.Helper()
	validator := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	return validator.ValidateCreate(context.Background(), importKeyForTest(importKey))
}

// The grammar is Garage v2.3's Key::import: ID >= 8 characters of
// [A-Za-z0-9-_.], secret >= 16 graphic ASCII characters (0x21-0x7E).
func TestImportKeyInlineGrammarMatchesGarage23(t *testing.T) {
	accept := map[string]ImportKeyConfig{
		"garage generated shape":      {AccessKeyID: importLegacyID, SecretAccessKey: importLegacySecret},
		"aws style":                   {AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		"minio style":                 {AccessKeyID: "minioadmin", SecretAccessKey: "minioadmin12345678"},
		"id exactly 8":                {AccessKeyID: "abcd1234", SecretAccessKey: strings.Repeat("s", 16)},
		"secret exactly 16":           {AccessKeyID: "abcd1234", SecretAccessKey: "0123456789abcdef"},
		"id with dash underscore dot": {AccessKeyID: "my-app_key.01", SecretAccessKey: strings.Repeat("s", 20)},
		"id not starting with GK":     {AccessKeyID: "tenant-a-key", SecretAccessKey: strings.Repeat("s", 20)},
		"secret with every symbol":    {AccessKeyID: "abcd1234", SecretAccessKey: "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"},
		"GK with non-hex letters":     {AccessKeyID: "GKnotHexButLongEnough", SecretAccessKey: strings.Repeat("s", 16)},
		"long values":                 {AccessKeyID: strings.Repeat("a", 128), SecretAccessKey: strings.Repeat("S", 256)},
	}
	for name, importKey := range accept {
		t.Run("accept/"+name, func(t *testing.T) {
			if _, err := validateImportKeyForTest(t, &importKey); err != nil {
				t.Fatalf("Garage v2.3 would accept this import: %v", err)
			}
		})
	}

	reject := map[string]struct {
		importKey ImportKeyConfig
		want      string
	}{
		"id one short of 8":       {ImportKeyConfig{AccessKeyID: "abcd123", SecretAccessKey: strings.Repeat("s", 16)}, "accessKeyId must be at least 8"},
		"old GK prefix too short": {ImportKeyConfig{AccessKeyID: "GKab", SecretAccessKey: strings.Repeat("s", 16)}, "accessKeyId must be at least 8"},
		"id with slash":           {ImportKeyConfig{AccessKeyID: "tenant/key01", SecretAccessKey: strings.Repeat("s", 16)}, "accessKeyId may contain only"},
		"id with space":           {ImportKeyConfig{AccessKeyID: "tenant key01", SecretAccessKey: strings.Repeat("s", 16)}, "accessKeyId may contain only"},
		"id with at sign":         {ImportKeyConfig{AccessKeyID: "user@example", SecretAccessKey: strings.Repeat("s", 16)}, "accessKeyId may contain only"},
		"id with colon":           {ImportKeyConfig{AccessKeyID: "tenant:key01", SecretAccessKey: strings.Repeat("s", 16)}, "accessKeyId may contain only"},
		"id non-ascii":            {ImportKeyConfig{AccessKeyID: "clé-secrète-01", SecretAccessKey: strings.Repeat("s", 16)}, "accessKeyId may contain only"},
		"id with newline":         {ImportKeyConfig{AccessKeyID: "abcdefgh\n", SecretAccessKey: strings.Repeat("s", 16)}, "accessKeyId may contain only"},
		"secret one short of 16":  {ImportKeyConfig{AccessKeyID: "abcd1234", SecretAccessKey: strings.Repeat("s", 15)}, "secretAccessKey must be at least 16"},
		"secret with space":       {ImportKeyConfig{AccessKeyID: "abcd1234", SecretAccessKey: "0123456789 abcdef"}, "secretAccessKey may contain only graphic ASCII"},
		"secret with tab":         {ImportKeyConfig{AccessKeyID: "abcd1234", SecretAccessKey: "0123456789\tabcdef"}, "secretAccessKey may contain only graphic ASCII"},
		"secret with newline":     {ImportKeyConfig{AccessKeyID: "abcd1234", SecretAccessKey: "0123456789abcdef\n"}, "secretAccessKey may contain only graphic ASCII"},
		"secret non-ascii":        {ImportKeyConfig{AccessKeyID: "abcd1234", SecretAccessKey: "0123456789abcdé€"}, "secretAccessKey may contain only graphic ASCII"},
		"secret with DEL":         {ImportKeyConfig{AccessKeyID: "abcd1234", SecretAccessKey: "0123456789abcdef\x7f"}, "secretAccessKey may contain only graphic ASCII"},
	}
	for name, tc := range reject {
		t.Run("reject/"+name, func(t *testing.T) {
			importKey := tc.importKey
			_, err := validateImportKeyForTest(t, &importKey)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
			// Credential material must never be echoed in admission errors.
			if strings.Contains(err.Error(), importKey.SecretAccessKey) {
				t.Fatalf("admission error echoes the secret: %v", err)
			}
		})
	}
}

func TestImportKeyPresenceRulesAreUnchanged(t *testing.T) {
	for name, tc := range map[string]struct {
		importKey ImportKeyConfig
		want      string
	}{
		"id without secret": {ImportKeyConfig{AccessKeyID: importLegacyID}, "secretAccessKey is required"},
		"secret without id": {ImportKeyConfig{SecretAccessKey: importLegacySecret}, "accessKeyId is required"},
		"empty":             {ImportKeyConfig{}, "specify secretRef or both"},
	} {
		t.Run(name, func(t *testing.T) {
			importKey := tc.importKey
			if _, err := validateImportKeyForTest(t, &importKey); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
		})
	}
	// Credentials read from a Secret are never inspected at admission.
	secretRef := &ImportKeyConfig{SecretRef: &corev1.SecretReference{Name: "existing-credentials"}}
	warnings, err := validateImportKeyForTest(t, secretRef)
	if err != nil {
		t.Fatalf("secretRef import rejected: %v", err)
	}
	if warningCount(warnings, "Garage v2.3.0 or newer") != 0 {
		t.Fatalf("secretRef import must not carry a version warning: %v", warnings)
	}
}

func warningCount(warnings []string, needle string) int {
	n := 0
	for _, warning := range warnings {
		if strings.Contains(warning, needle) {
			n++
		}
	}
	return n
}

// Garage v2.0 to v2.2 accept only the shape Garage generates. Anything else
// passes admission but warns, and Garage's own 400 is reported in status.
func TestImportKeyWarnsWhenOnlyGarage23AcceptsTheCredentials(t *testing.T) {
	for name, tc := range map[string]struct {
		importKey ImportKeyConfig
		wantWarns int
		contains  []string
	}{
		"generated shape":            {ImportKeyConfig{AccessKeyID: importLegacyID, SecretAccessKey: importLegacySecret}, 0, nil},
		"generated shape upper hex":  {ImportKeyConfig{AccessKeyID: "GK0123456789ABCDEF01234567", SecretAccessKey: strings.ToUpper(importLegacySecret)}, 0, nil},
		"aws id and secret":          {ImportKeyConfig{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, 1, []string{"accessKeyId is not 'GK' followed by 24 hex characters", "secretAccessKey is not 64 hex characters"}},
		"legacy id, relaxed secret":  {ImportKeyConfig{AccessKeyID: importLegacyID, SecretAccessKey: strings.Repeat("s", 20)}, 1, []string{"secretAccessKey is not 64 hex characters"}},
		"relaxed id, legacy secret":  {ImportKeyConfig{AccessKeyID: "tenant-a-key", SecretAccessKey: importLegacySecret}, 1, []string{"accessKeyId is not 'GK'"}},
		"GK too long":                {ImportKeyConfig{AccessKeyID: importLegacyID + "00", SecretAccessKey: importLegacySecret}, 1, []string{"accessKeyId is not 'GK'"}},
		"GK with non-hex":            {ImportKeyConfig{AccessKeyID: "GK0123456789abcdef0123456z", SecretAccessKey: importLegacySecret}, 1, []string{"accessKeyId is not 'GK'"}},
		"secret one hex digit short": {ImportKeyConfig{AccessKeyID: importLegacyID, SecretAccessKey: importLegacySecret[:63]}, 1, []string{"secretAccessKey is not 64 hex"}},
	} {
		t.Run(name, func(t *testing.T) {
			importKey := tc.importKey
			warnings, err := validateImportKeyForTest(t, &importKey)
			if err != nil {
				t.Fatalf("warning cases must still be admitted: %v", err)
			}
			if got := warningCount(warnings, "Garage v2.3.0 or newer"); got != tc.wantWarns {
				t.Fatalf("version warnings = %d, want %d: %v", got, tc.wantWarns, warnings)
			}
			for _, want := range tc.contains {
				if warningCount(warnings, want) != 1 {
					t.Errorf("warnings missing %q: %v", want, warnings)
				}
			}
			for _, warning := range warnings {
				if strings.Contains(warning, importKey.SecretAccessKey) {
					t.Errorf("warning echoes the secret: %s", warning)
				}
			}
		})
	}
}

// A key that an older operator admitted under the previous GK-prefix regex and
// that is now outside the Garage grammar must not wedge: spec edits that leave
// importKey untouched (finalizer removal, label changes) are still admitted.
func TestImportKeyLegacyValueDoesNotBlockUnrelatedUpdates(t *testing.T) {
	validator := &GarageKeyValidator{Client: fake.NewClientBuilder().WithScheme(fakeScheme(t)).Build()}
	old := importKeyForTest(&ImportKeyConfig{AccessKeyID: "GKab", SecretAccessKey: "short"})
	// The API server stores the defaulted object, so both sides of an update
	// have been through the defaulter.
	if err := (&GarageKeyDefaulter{}).Default(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	updated := old.DeepCopy()
	updated.Labels = map[string]string{"touched": "true"}
	if _, err := validator.ValidateUpdate(context.Background(), old, updated); err != nil {
		t.Fatalf("unrelated update of a previously admitted object was rejected: %v", err)
	}
	// A new object with the same value is rejected.
	fresh := importKeyForTest(old.Spec.ImportKey.DeepCopy())
	if _, err := validator.ValidateCreate(context.Background(), fresh); err == nil {
		t.Fatal("a new GarageKey with a malformed inline import was admitted")
	}
}
