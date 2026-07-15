// SPDX-License-Identifier: Apache-2.0
package resolver

import "testing"

// TestWildcardVolatile: operand data (rel32 / imm32) is masked; opcode, ModRM and
// 1-byte immediates (stack-frame sizes — stable discriminators) stay fixed.
func TestWildcardVolatile(t *testing.T) {
	code := []byte{
		0x55,             // push rbp
		0x48, 0x89, 0xe5, // mov rbp, rsp
		0xe8, 0x11, 0x22, 0x33, 0x44, // call rel32  -> mask [5..8]
		0xba, 0xaa, 0xbb, 0xcc, 0xdd, // mov edx, imm32 -> mask [10..13]
		0x48, 0x83, 0xec, 0x28, // sub rsp, 0x28 -> imm8 kept (run length 1)
	}
	pb := wildcardVolatile(code)
	if len(pb) != len(code) {
		t.Fatalf("len %d != %d", len(pb), len(code))
	}
	wantWild := map[int]bool{5: true, 6: true, 7: true, 8: true, 10: true, 11: true, 12: true, 13: true}
	for i := range code {
		if pb[i].wildcard != wantWild[i] {
			t.Errorf("byte %d (0x%02x): wildcard=%v want %v", i, code[i], pb[i].wildcard, wantWild[i])
		}
	}
	// Fixed bytes must keep their value (incl. the imm8 frame size 0x28).
	if pb[17].wildcard || pb[17].val != 0x28 {
		t.Errorf("imm8 frame size should be fixed 0x28, got wildcard=%v val=0x%02x", pb[17].wildcard, pb[17].val)
	}
}

// TestSolveByDistanceLocalDrift: distances are only locally stable. Unique matches
// pin directly; an ambiguous key resolves against its NEAREST pinned neighbour, so
// a far-key drift (handshake↔read) does not defeat a rigid near pair (read↔write).
func TestSolveByDistanceLocalDrift(t *testing.T) {
	cands := map[string][]uint64{
		"handshake": {1000},             // unique
		"read":      {5000},             // unique
		"write":     {5912, 8000, 9000}, // ambiguous; correct = read+912
	}
	refs := map[string]uint64{
		"handshake": 100,  // handshake↔read ref delta 3900, actual 4000 (drift +100)
		"read":      4000, // read↔write ref delta 912 (rigid)
		"write":     4912,
	}
	out, ok := solveByDistance(cands, refs)
	if !ok {
		t.Fatal("expected resolution")
	}
	want := map[string]uint64{"handshake": 1000, "read": 5000, "write": 5912}
	for k, v := range want {
		if out[k] != v {
			t.Errorf("%s = %d, want %d", k, out[k], v)
		}
	}
}

// TestSolveByDistanceAllAmbiguous: with no unique match (identical thin-wrapper
// prologues) the single-anchor fallback still pins via consistent deltas.
func TestSolveByDistanceAllAmbiguous(t *testing.T) {
	cands := map[string][]uint64{
		"read":  {2000, 5000},
		"write": {2912, 6000}, // read+912 = 2912 is the consistent pair
	}
	refs := map[string]uint64{"read": 4000, "write": 4912}
	out, ok := solveByDistance(cands, refs)
	if !ok {
		t.Fatal("expected resolution")
	}
	if out["read"] != 2000 || out["write"] != 2912 {
		t.Errorf("got read=%d write=%d, want 2000/2912", out["read"], out["write"])
	}
}
