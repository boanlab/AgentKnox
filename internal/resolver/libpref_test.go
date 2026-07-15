// SPDX-License-Identifier: Apache-2.0
package resolver

import "testing"

// TestFindTLSLibraryPreference: libssl must win regardless of maps order;
// boringssl/libcrypto are fallbacks (libcrypto has no SSL_read/SSL_write).
func TestFindTLSLibraryPreference(t *testing.T) {
	// Mirror the selection logic against a synthetic maps ordering where libcrypto
	// appears first (lower address), as it does in a real process.
	got := pickTLSLib([]string{
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
	})
	if got != "/usr/lib/x86_64-linux-gnu/libssl.so.3" {
		t.Errorf("preferred %q, want libssl", got)
	}
	// Only libcrypto present ⇒ fallback to it (AEAD/T7 path).
	if got := pickTLSLib([]string{"/x/libcrypto.so.3"}); got != "/x/libcrypto.so.3" {
		t.Errorf("libcrypto fallback failed: %q", got)
	}
	// Static boringssl object.
	if got := pickTLSLib([]string{"/x/libcrypto.so.3", "/x/boringssl.so"}); got != "/x/boringssl.so" {
		t.Errorf("boringssl preferred over libcrypto: got %q", got)
	}
}
