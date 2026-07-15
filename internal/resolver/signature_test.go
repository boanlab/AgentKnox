// SPDX-License-Identifier: Apache-2.0
package resolver

import (
	"debug/elf"
	"testing"
)

// TestT5SignatureRoundTrip exercises the full T5 path against real BoringSSL/
// OpenSSL code: extract prologue signatures + reference offsets from a symboled
// library, then scan that same code and recover the offsets — including
// disambiguating the identical SSL_read/SSL_write wrapper prologues by their
// reference inter-function distance (the technique the AgentSight/eunomia writeup
// uses on stripped Claude Code). Skips if the system libssl is unavailable.
func TestT5SignatureRoundTrip(t *testing.T) {
	const lib = "/lib/x86_64-linux-gnu/libssl.so.3"
	if _, err := elf.Open(lib); err != nil {
		t.Skip("system libssl not available")
	}
	prov, pats, refOffs, err := ExtractSignatures(lib, 24)
	if err != nil {
		t.Fatal(err)
	}
	if len(pats) < 2 {
		t.Fatalf("expected >=2 signatures, got %d", len(pats))
	}
	var sigs []signature
	for k, p := range pats {
		pb, err := parsePattern(p)
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, signature{provider: prov, key: k, pattern: pb, refOff: refOffs[k]})
	}
	f, err := elf.Open(lib)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, ok := resolvePatternMatchWith(f, sigs, prov)
	if !ok {
		t.Fatal("T5 failed to recover offsets from real code")
	}
	for k, want := range refOffs {
		if got[k] != want {
			t.Errorf("%s: recovered %#x, want %#x", k, got[k], want)
		}
	}
	if r, w := got["read"], got["write"]; r != 0 && w != 0 && r == w {
		t.Error("read and write resolved to the same offset (distance disambiguation failed)")
	}
}
