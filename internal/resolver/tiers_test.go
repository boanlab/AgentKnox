// SPDX-License-Identifier: Apache-2.0
package resolver

import "testing"

// TestT5PatternParse covers pattern parsing (hex bytes + wildcards + length gate).
func TestT5PatternParse(t *testing.T) {
	if _, err := parsePattern("55 48 89"); err == nil {
		t.Error("too-short pattern should error")
	}
	p, err := parsePattern("55 48 89 e5 ?? 57 41 56")
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 8 || !p[4].wildcard || p[0].val != 0x55 {
		t.Errorf("bad parse: %+v", p)
	}
}

// TestT6DisasmFollowCall covers the T6 disassembler following a direct near CALL.
func TestT6DisasmFollowCall(t *testing.T) {
	// push rbp; mov rbp,rsp; call +7; nops; ret. CALL ends at offset 9, +7 = 0x10.
	text := []byte{0x55, 0x48, 0x89, 0xe5, 0xe8, 0x07, 0x00, 0x00, 0x00,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3}
	tgt, ok := disasmFollowCall(text, 0x1000, 0x1000, 16)
	if !ok || tgt != 0x1010 {
		t.Fatalf("disasmFollowCall = (%#x,%v), want (0x1010,true)", tgt, ok)
	}
	// RET before any CALL ⇒ false.
	if _, ok := disasmFollowCall([]byte{0x55, 0x48, 0x89, 0xe5, 0xc3}, 0x1000, 0x1000, 16); ok {
		t.Error("RET-before-CALL must return false")
	}
}

// TestProviderFor covers TLS-provider classification from library/version labels.
func TestProviderFor(t *testing.T) {
	cases := map[string]string{
		"<self> BoringSSL 1.1":       "boringssl",
		"libssl.so.3 OpenSSL 3.0.13": "openssl",
		"foo aws-lc 1.0":             "aws-lc",
		"<self> ":                    "",
	}
	for in, want := range cases {
		parts := splitLibVer(in)
		if got := providerFor(parts[0], parts[1]); got != want {
			t.Errorf("providerFor(%q) = %q, want %q", in, got, want)
		}
	}
}

func splitLibVer(s string) [2]string {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return [2]string{s[:i], s[i+1:]}
		}
	}
	return [2]string{s, ""}
}
