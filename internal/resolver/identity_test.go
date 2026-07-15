// SPDX-License-Identifier: Apache-2.0
package resolver

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"github.com/boanlab/agentknox/pkg/types"
)

// identityFixture returns a system binary that carries a GNU build-id, and that
// build-id. It skips when no such binary is available.
func identityFixture(t *testing.T) (string, string) {
	t.Helper()
	for _, p := range []string{"/bin/true", "/usr/bin/true", "/bin/cat", "/usr/bin/cat"} {
		f, err := elf.Open(p)
		if err != nil {
			continue
		}
		bid := readBuildID(f)
		f.Close()
		if bid != "" {
			return p, bid
		}
	}
	t.Skip("no system binary with a build-id available")
	return "", ""
}

func writeOffsetDB(t *testing.T, entries map[string]map[string]uint64) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "offsetdb")
	b, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestKnownGoodIsDecidedForEveryTier: the known-good verdict comes from the
// reference set itself, not from the rung that serves the offsets. An unstripped
// binary resolves at T1 and never consults the offset database, so a verdict
// decided at the serving rung would report every such build as unvouched-for.
func TestKnownGoodIsDecidedForEveryTier(t *testing.T) {
	bin, bid := identityFixture(t)
	target := targetBinary{binaryPath: bin, library: "<self>"}

	// (a) a reference set that does not list this build-id: identified, not vouched for.
	r := New(writeOffsetDB(t, map[string]map[string]uint64{"00deadbeef": {"read": 1}}), zap.NewNop())
	plan, err := r.resolveScan(0, types.AgentUnknown, target)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if plan.BuildID != bid {
		t.Fatalf("build-id: got %q want %q", plan.BuildID, bid)
	}
	if !plan.ReferenceSet {
		t.Error("a loaded, non-empty reference set must be reported as consulted")
	}
	if plan.KnownGood {
		t.Error("a build-id absent from the reference set must not be vouched for")
	}

	// (b) the same build-id listed: vouched for.
	r = New(writeOffsetDB(t, map[string]map[string]uint64{bid: {"read": 1, "write": 2}}), zap.NewNop())
	plan, err = r.resolveScan(0, types.AgentUnknown, target)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !plan.KnownGood {
		t.Error("a build-id the reference set lists must be vouched for")
	}

	// (c) no reference set at all: nothing could vouch for the binary, which is not
	// the same as a binary nothing vouches for.
	r = New("", zap.NewNop())
	plan, err = r.resolveScan(0, types.AgentUnknown, target)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if plan.ReferenceSet || plan.KnownGood {
		t.Errorf("with no reference set: ReferenceSet=%v KnownGood=%v, want both false",
			plan.ReferenceSet, plan.KnownGood)
	}
}

// TestIdentityChangedOnRestampedBuild: the same code section under a different
// build-id is an identity that changed while the code did not. The fixture patches
// only the build-id note, so .text is byte-identical.
func TestIdentityChangedOnRestampedBuild(t *testing.T) {
	bin, bid := identityFixture(t)
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Skipf("cannot read %s: %v", bin, err)
	}
	idBytes, err := hex.DecodeString(bid)
	if err != nil || len(idBytes) == 0 {
		t.Skipf("build-id %q is not hex", bid)
	}
	idx := bytes.Index(raw, idBytes)
	if idx < 0 {
		t.Skip("build-id bytes not locatable in the file image")
	}
	raw[idx] ^= 0xff // restamp the identity; the code section is untouched
	restamped := filepath.Join(t.TempDir(), "restamped")
	if err := os.WriteFile(restamped, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	r := New("", zap.NewNop())
	first, err := r.resolveScan(0, types.AgentUnknown, targetBinary{binaryPath: bin, library: "<self>"})
	if err != nil {
		t.Fatalf("resolve original: %v", err)
	}
	if first.IdentityChanged {
		t.Error("the first sighting of a build cannot be an identity change")
	}
	second, err := r.resolveScan(0, types.AgentUnknown, targetBinary{binaryPath: restamped, library: "<self>"})
	if err != nil {
		t.Fatalf("resolve restamped: %v", err)
	}
	if second.BuildID == first.BuildID {
		t.Fatalf("fixture did not change the build-id (%q)", second.BuildID)
	}
	if !second.IdentityChanged {
		t.Error("same code section under a different build-id must report an identity change")
	}
}
