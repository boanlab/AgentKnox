// SPDX-License-Identifier: Apache-2.0
package enforce

import (
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	"github.com/boanlab/agentknox/internal/bpf2frame"
	"github.com/boanlab/agentknox/internal/pipeline"
	"github.com/boanlab/agentknox/pkg/types"
)

func TestIsExactPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/etc/shadow", true},
		{"/usr/bin/curl", true},
		{"/etc/", false},        // directory prefix
		{"/etc/ssh/", false},    // directory prefix
		{"/home/*/.ssh", false}, // wildcard
		{"/var/log/*.log", false},
		{"/data/[abc]/x", false}, // char class
		{"/foo?bar", false},      // single-char wildcard
		{"relative/path", false}, // not absolute
		{"", false},              // empty
	}
	for _, c := range cases {
		if got := isExactPath(c.path); got != c.want {
			t.Errorf("isExactPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestHasBPFLSM(t *testing.T) {
	cases := []struct {
		list string
		want bool
	}{
		{"lockdown,capability,yama,apparmor,bpf", true},
		{"bpf", true},
		{"capability, bpf ,landlock", true}, // spaces tolerated
		{"capability,yama,apparmor", false},
		{"apparmor", false},
		{"", false},
		{"bpfx", false}, // must be exact token, not substring
	}
	for _, c := range cases {
		if got := hasBPFLSM(c.list); got != c.want {
			t.Errorf("hasBPFLSM(%q) = %v, want %v", c.list, got, c.want)
		}
	}
}

func TestSelectBackend(t *testing.T) {
	log := zap.NewNop()

	e := SelectBackend("auto", "lockdown,capability,bpf", Maps{}, false, log)
	if e.Backend() != "bpf-lsm" {
		t.Errorf("with bpf LSM: Backend() = %q, want bpf-lsm", e.Backend())
	}

	e = SelectBackend("auto", "capability,yama,apparmor", Maps{}, false, log)
	if e.Backend() != "userspace" {
		t.Errorf("without bpf LSM: Backend() = %q, want userspace", e.Backend())
	}
}

func TestBPFEnforcerBackend(t *testing.T) {
	if b := New(Maps{}, false, nil).Backend(); b != "bpf-lsm" {
		t.Errorf("Backend() = %q, want bpf-lsm", b)
	}
}

// TestApplyKillDryRun verifies dry-run never sends a signal and reports no error.
func TestApplyKillDryRun(t *testing.T) {
	e := New(Maps{}, true /*dryRun*/, zap.NewNop())
	sess := &types.AgentSession{ID: "s1", RootPID: 1234567} // pid unlikely to exist
	d := types.Decision{Effect: types.EffectKill, PolicyName: "p"}
	if err := e.Apply(sess, d, nil); err != nil {
		t.Fatalf("dry-run kill returned error: %v", err)
	}
}

// TestApplyKillGuardsInit ensures pid<=1 is never targeted.
func TestApplyKillGuardsInit(t *testing.T) {
	e := New(Maps{}, false, zap.NewNop())
	sess := &types.AgentSession{ID: "s1", RootPID: 1, Members: []int32{0, -5}}
	d := types.Decision{Effect: types.EffectKill}
	err := e.Apply(sess, d, nil)
	if err == nil {
		t.Fatal("expected error when no valid target pid, got nil")
	}
}

// TestUserspaceBlockDegradesToAlert: without BPF-LSM the repertoire is
// alert + kill only — a Block decision must not terminate anything.
func TestUserspaceBlockDegradesToAlert(t *testing.T) {
	u := NewUserspace(false, zap.NewNop())
	sess := &types.AgentSession{ID: "s1", RootPID: int32(syscall.Getpid())}
	d := types.Decision{Effect: types.EffectBlock, PolicyName: "p"}
	if err := u.Apply(sess, d, nil); err != nil {
		t.Fatalf("Apply(Block) returned error: %v", err)
	}
	// If Block had escalated to kill, this test process would be dead by now.
}

// TestApplyNoActionEffects ensures Allow/Audit/Alert do nothing and don't error.
func TestApplyNoActionEffects(t *testing.T) {
	e := New(Maps{}, false, zap.NewNop())
	for _, eff := range []types.PolicyEffect{types.EffectAllow, types.EffectAudit, types.EffectAlert} {
		if err := e.Apply(nil, types.Decision{Effect: eff}, nil); err != nil {
			t.Errorf("Apply(%s) returned error: %v", eff, err)
		}
	}
}

// newTestHashMap creates a real in-kernel HASH map (u64->u32). It requires
// CAP_BPF/root; tests skip when unavailable.
func newTestHashMap(t *testing.T) *ebpf.Map { return newTestHashMapN(t, 64) }

// newTestHashMapN is newTestHashMap with an explicit capacity, so a test can
// force the map-full path.
func newTestHashMapN(t *testing.T, entries uint32) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: entries,
	})
	if err != nil {
		t.Skipf("cannot create BPF HASH map (needs CAP_BPF/root): %v", err)
	}
	return m
}

// TestInstallRulesContinuesPastMapOverflow proves the rule set is not abandoned
// at the first refusal: with a file map that holds two entries, the third and
// fourth exact-path rules are dropped, yet the directory rule that follows them
// (a different map) is still installed, and the error names how many were dropped
// and which map refused them.
func TestInstallRulesContinuesPastMapOverflow(t *testing.T) {
	enforceFile := newTestHashMapN(t, 2)
	defer enforceFile.Close()
	enforceDir := newTestHashMap(t)
	defer enforceDir.Close()

	e := New(Maps{EnforceFile: enforceFile, EnforceDir: enforceDir}, false, zap.NewNop())

	rules := []pipeline.KernelRule{
		{PolicyName: "f1", Category: types.CategoryFile, PathPrefix: "/etc/shadow", Effect: types.EffectBlock},
		{PolicyName: "f2", Category: types.CategoryFile, PathPrefix: "/etc/gshadow", Effect: types.EffectBlock},
		{PolicyName: "f3", Category: types.CategoryFile, PathPrefix: "/etc/sudoers", Effect: types.EffectBlock},
		{PolicyName: "f4", Category: types.CategoryFile, PathPrefix: "/root/.ssh/authorized_keys", Effect: types.EffectBlock},
		// Ordered AFTER the overflow on purpose: it must still be installed.
		{PolicyName: "d1", Category: types.CategoryFile, PathPrefix: "/var/lib/agentknox/", Effect: types.EffectBlock},
	}
	err := e.InstallRules(rules)
	if err == nil {
		t.Fatal("expected an error reporting the dropped rules")
	}
	msg := err.Error()
	for _, want := range []string{"2 of 5", "ak_enforce_file", "2 dropped"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q should mention %q", msg, want)
		}
	}
	// The rule after the overflow reached its own map.
	var got uint32
	if err := enforceDir.Lookup(bpf2frame.HashString("/var/lib/agentknox"), &got); err != nil {
		t.Fatalf("directory rule after the overflow should still be installed: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestInstallRulesRoundTrip exercises the real map path when privileged.
func TestInstallRulesRoundTrip(t *testing.T) {
	enforceFile := newTestHashMap(t)
	defer enforceFile.Close()
	enforceDir := newTestHashMap(t)
	defer enforceDir.Close()
	sessions := newTestHashMap(t)
	defer sessions.Close()

	e := New(Maps{Sessions: sessions, EnforceFile: enforceFile, EnforceDir: enforceDir}, false, zap.NewNop())

	rules := []pipeline.KernelRule{
		{PolicyName: "block-shadow", Category: types.CategoryFile, PathPrefix: "/etc/shadow", Effect: types.EffectBlock},
		{PolicyName: "block-dir", Category: types.CategoryFile, PathPrefix: "/etc/ssh/", Effect: types.EffectBlock},     // directory rule: own map
		{PolicyName: "block-glob", Category: types.CategoryFile, PathPrefix: "/home/*/.ssh", Effect: types.EffectBlock}, // wildcard: skipped
		{PolicyName: "allow", Category: types.CategoryFile, PathPrefix: "/tmp/x", Effect: types.EffectAllow},            // non-block: skipped
	}
	if err := e.InstallRules(rules); err != nil {
		t.Fatalf("InstallRules: %v", err)
	}

	// Only the exact-path block rule should be present in the file map.
	h := bpf2frame.HashString("/etc/shadow")
	var got uint32
	if err := enforceFile.Lookup(h, &got); err != nil {
		t.Fatalf("expected /etc/shadow hash installed: %v", err)
	}
	if got != opOpen {
		t.Errorf("action for /etc/shadow = %d, want %d", got, opOpen)
	}

	// The directory rule lands in the directory map (hashed without the trailing
	// slash), never in the exact-path map.
	if err := enforceFile.Lookup(bpf2frame.HashString("/etc/ssh/"), &got); err == nil {
		t.Errorf("directory rule should not be in the exact-path map")
	}
	if err := enforceDir.Lookup(bpf2frame.HashString("/etc/ssh"), &got); err != nil {
		t.Errorf("directory rule should be installed in the directory map: %v", err)
	}

	// EnforceSession sets monitor|enforce for non-dry-run.
	sess := &types.AgentSession{ID: "s1", CgroupID: 42}
	if err := e.EnforceSession(sess); err != nil {
		t.Fatalf("EnforceSession: %v", err)
	}
	var flags uint32
	if err := sessions.Lookup(uint64(42), &flags); err != nil {
		t.Fatalf("session flags lookup: %v", err)
	}
	if flags != sessMonitor|sessEnforce {
		t.Errorf("flags = %#x, want %#x", flags, sessMonitor|sessEnforce)
	}

	// Close clears installed entries.
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := enforceFile.Lookup(h, &got); err == nil {
		t.Errorf("Close should have removed installed hash")
	}
}

// TestEnforceSessionDryRun verifies dry-run sets monitor only (no enforce bit).
func TestEnforceSessionDryRun(t *testing.T) {
	sessions := newTestHashMap(t)
	defer sessions.Close()

	e := New(Maps{Sessions: sessions}, true /*dryRun*/, zap.NewNop())
	sess := &types.AgentSession{ID: "s1", CgroupID: 7}
	if err := e.EnforceSession(sess); err != nil {
		t.Fatalf("EnforceSession: %v", err)
	}
	var flags uint32
	if err := sessions.Lookup(uint64(7), &flags); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if flags != sessMonitor {
		t.Errorf("dry-run flags = %#x, want %#x (monitor only)", flags, sessMonitor)
	}
}
