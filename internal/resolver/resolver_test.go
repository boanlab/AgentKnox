// SPDX-License-Identifier: Apache-2.0
package resolver

import (
	"debug/elf"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"github.com/boanlab/agentknox/pkg/types"
)

// TestVaddrToFileOffset exercises the VA→file-offset conversion against a
// synthetic ELF whose loadable segment maps vaddr 0x1000 to file offset 0x200.
func TestVaddrToFileOffset(t *testing.T) {
	f := &elf.File{
		Progs: []*elf.Prog{
			{ProgHeader: elf.ProgHeader{
				Type: elf.PT_LOAD, Vaddr: 0x1000, Off: 0x200, Filesz: 0x1000,
			}},
			{ProgHeader: elf.ProgHeader{
				Type: elf.PT_LOAD, Vaddr: 0x400000, Off: 0x0, Filesz: 0x100,
			}},
		},
	}
	cases := []struct {
		vaddr   uint64
		wantOff uint64
		wantOK  bool
	}{
		{0x1000, 0x200, true},  // segment start
		{0x1234, 0x434, true},  // mid-segment: 0x1234 - 0x1000 + 0x200
		{0x1fff, 0x11ff, true}, // last mapped byte
		{0x2000, 0, false},     // just past Filesz
		{0x400050, 0x50, true}, // second segment
		{0x999999, 0, false},   // unmapped
	}
	for _, c := range cases {
		off, ok := vaddrToFileOffset(f, c.vaddr)
		if ok != c.wantOK || (ok && off != c.wantOff) {
			t.Errorf("vaddrToFileOffset(%#x) = (%#x,%v), want (%#x,%v)",
				c.vaddr, off, ok, c.wantOff, c.wantOK)
		}
	}
}

func TestCoverageFor(t *testing.T) {
	full := map[string]uint64{keyRead: 1, keyWrite: 2}
	if got := coverageFor(full); got != types.CoverageFull {
		t.Errorf("both read+write: got %v want full", got)
	}
	if got := coverageFor(map[string]uint64{keyWrite: 2}); got != types.CoverageDegraded {
		t.Errorf("write only: got %v want degraded", got)
	}
	if got := coverageFor(map[string]uint64{}); got != types.CoverageNone {
		t.Errorf("empty: got %v want none", got)
	}
	if got := coverageForAEAD(map[string]uint64{keyAEADOpen: 1, keyAEADSeal: 2}); got != types.CoverageFull {
		t.Errorf("aead both: got %v want full", got)
	}
}

func TestLoadOffsetDB(t *testing.T) {
	// Missing file is tolerated.
	db, err := LoadOffsetDB(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing db should not error: %v", err)
	}
	if len(db) != 0 {
		t.Fatalf("missing db should be empty, got %d", len(db))
	}
	// Empty path tolerated.
	if _, err := LoadOffsetDB(""); err != nil {
		t.Fatalf("empty path: %v", err)
	}

	// Round-trip a real DB file.
	want := map[string]map[string]uint64{
		"deadbeef": {"read": 123, "write": 456, "handshake": 789},
	}
	path := filepath.Join(t.TempDir(), "db.json")
	buf, _ := json.Marshal(want)
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOffsetDB(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got["deadbeef"]["write"] != 456 {
		t.Fatalf("offset mismatch: %+v", got)
	}

	// Malformed JSON is an error.
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte("{not json"), 0o644)
	if _, err := LoadOffsetDB(bad); err == nil {
		t.Fatal("malformed db should error")
	}
}

func TestApplyDBAEAD(t *testing.T) {
	r := New("", zap.NewNop())
	plan := &types.AttachPlan{Offsets: map[string]uint64{}}
	r.applyDB(plan, map[string]uint64{"aead_open": 10, "aead_seal": 20})
	if plan.Boundary != types.BoundaryAEAD {
		t.Errorf("boundary: got %v want aead", plan.Boundary)
	}
	if plan.Tier != types.TierOffsetDB || !plan.KnownGood {
		t.Errorf("expected T4 known-good, got %v knownGood=%v", plan.Tier, plan.KnownGood)
	}
	if plan.Coverage != types.CoverageFull {
		t.Errorf("coverage: got %v want full", plan.Coverage)
	}
}

// TestResolveSelf resolves against the test process itself. Go binaries are
// statically linked and stripped of SSL exports, so this typically yields a
// degraded/none plan — the point is that Resolve never errors on a live pid and
// produces a well-formed plan (build-id fingerprint, self binary path).
func TestResolveSelf(t *testing.T) {
	r := New("", zap.NewNop())
	plan, err := r.Resolve(int32(os.Getpid()), types.AgentUnknown)
	if err != nil {
		t.Fatalf("resolve self: %v", err)
	}
	if plan == nil {
		t.Fatal("nil plan")
	}
	if plan.BinaryPath == "" {
		t.Error("expected a binary path")
	}
	if plan.Offsets == nil {
		t.Error("offsets map must be non-nil")
	}
	t.Logf("self plan: binary=%s library=%s buildid=%s tier=%s coverage=%s boundary=%s",
		plan.BinaryPath, plan.Library, plan.BuildID, plan.Tier, plan.Coverage, plan.Boundary)
}

// TestResolveLibssl looks for a system libssl and, if the current process has it
// mapped or one exists on disk, exercises the T1/T2 symbol path. Skips cleanly
// when no libssl is available.
func TestResolveLibssl(t *testing.T) {
	candidates := []string{
		"/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/usr/lib64/libssl.so.3",
	}
	var lib string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			lib = c
			break
		}
	}
	if lib == "" {
		t.Skip("no system libssl found; skipping symbol-resolution test")
	}
	f, err := elf.Open(lib)
	if err != nil {
		t.Skipf("cannot open %s: %v", lib, err)
	}
	defer f.Close()

	offs := symbolOffsets(f, f.DynamicSymbols)
	if len(offs) == 0 {
		offs = symbolOffsets(f, f.Symbols)
	}
	if len(offs) == 0 {
		t.Skipf("%s has no SSL symbols (stripped); nothing to verify", lib)
	}
	// Every recovered offset must fall inside the file.
	fi, _ := os.Stat(lib)
	for k, off := range offs {
		if off == 0 || off >= uint64(fi.Size()) {
			t.Errorf("offset %s=%#x out of range for %s (size %d)", k, off, lib, fi.Size())
		}
		t.Logf("%s %s -> file offset %#x", lib, k, off)
	}
}
