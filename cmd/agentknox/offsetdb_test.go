// SPDX-License-Identifier: Apache-2.0
package main

import "testing"

func TestParseManualSet(t *testing.T) {
	id, offs, err := parseManualSet("abc123:read=0x1a2b3c,write=0x1a2b90,aead_open=0xff")
	if err != nil {
		t.Fatal(err)
	}
	if id != "abc123" {
		t.Errorf("build-id = %q", id)
	}
	if offs["read"] != 0x1a2b3c || offs["write"] != 0x1a2b90 || offs["aead_open"] != 0xff {
		t.Errorf("offsets = %v", offs)
	}
	// Unknown key rejected.
	if _, _, err := parseManualSet("abc:bogus=0x1"); err == nil {
		t.Error("unknown offset key should error")
	}
	// Missing build-id rejected.
	if _, _, err := parseManualSet("read=0x1"); err == nil {
		t.Error("missing build-id should error")
	}
	// Bad hex rejected.
	if _, _, err := parseManualSet("abc:read=nothex"); err == nil {
		t.Error("bad hex should error")
	}
}
