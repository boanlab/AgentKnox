// SPDX-License-Identifier: Apache-2.0
package resolver

import (
	"os"
	"testing"

	"github.com/boanlab/agentknox/pkg/types"
)

// TestFingerprintDeterministic: the same binary yields the same fingerprint, and
// two different binaries yield different fingerprints (so cache entries don't
// collide across builds).
func TestFingerprintDeterministic(t *testing.T) {
	r := New("", nil)
	self, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable: %v", err)
	}
	fp1 := r.fingerprint(self)
	fp2 := r.fingerprint(self)
	if fp1 == "" {
		t.Fatal("fingerprint of self is empty")
	}
	if fp1 != fp2 {
		t.Fatalf("fingerprint not deterministic: %q != %q", fp1, fp2)
	}
	if other := r.fingerprint("/bin/sh"); other != "" && other == fp1 {
		t.Fatalf("distinct binaries share a fingerprint: %q", fp1)
	}
	if empty := r.fingerprint("/no/such/binary"); empty != "" {
		t.Fatalf("fingerprint of missing file should be empty, got %q", empty)
	}
}

// TestRetargetPlanDeepCopies: a cached plan reused for another process must not
// share the offsets map (else concurrent processes could mutate a shared entry)
// and must carry the new process's binary path.
func TestRetargetPlanDeepCopies(t *testing.T) {
	cached := &types.AttachPlan{
		BinaryPath: "/orig/codex",
		Library:    "<self>",
		Boundary:   types.BoundaryAEADAsm,
		Coverage:   types.CoverageFull,
		Offsets:    map[string]uint64{"chacha_open": 0x1000},
	}
	got := retargetPlan(cached, targetBinary{binaryPath: "/tmp/arg0/codex-xyz", library: "<self>"})
	if got.BinaryPath != "/tmp/arg0/codex-xyz" {
		t.Fatalf("BinaryPath = %q, want retargeted", got.BinaryPath)
	}
	if got.Offsets["chacha_open"] != 0x1000 {
		t.Fatalf("offsets not carried over: %v", got.Offsets)
	}
	// Mutating the copy must not touch the cached entry.
	got.Offsets["chacha_open"] = 0x2000
	if cached.Offsets["chacha_open"] != 0x1000 {
		t.Fatal("retargetPlan did not deep-copy offsets; cache entry was mutated")
	}
}
