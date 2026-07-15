// SPDX-License-Identifier: Apache-2.0
package resolver

import (
	"path/filepath"
	"testing"
)

// Every provider the shipped signature database carries must be one the resolve
// ladder actually asks the pattern matcher for. The matcher requires an exact
// provider match, so a family the ladder never names is dead weight: its
// signatures sit in the database while the binaries they were extracted for fall
// through every rung to a none-coverage plan.
//
// This is a contract between two places that do not reference each other:
// ExtractSignatures stamps the provider, and resolve() chooses which providers to
// try.
func TestShippedSignatureProvidersAreReachable(t *testing.T) {
	sigs, err := loadSignatures(filepath.Join("..", "..", "deployments", "signatures.json"))
	if err != nil {
		t.Fatalf("loadSignatures: %v", err)
	}
	if len(sigs) == 0 {
		t.Fatal("shipped signature database is empty")
	}

	// The providers resolve() can name: those providerFor derives from the library
	// string, plus the assembly family it tries explicitly.
	reachable := map[string]bool{providerAEADAsm: true}
	for _, lib := range []string{"boringssl", "aws-lc", "openssl"} {
		reachable[providerFor(lib, "")] = true
	}

	seen := map[string]bool{}
	for _, s := range sigs {
		seen[s.provider] = true
	}
	for provider := range seen {
		if !reachable[provider] {
			t.Errorf("signature provider %q is in the database but no rung of the ladder asks for it", provider)
		}
	}
	if !seen[providerAEADAsm] {
		t.Errorf("no %q signatures shipped; the stripped static-binary rung has nothing to match", providerAEADAsm)
	}
}
