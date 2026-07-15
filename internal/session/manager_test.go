// SPDX-License-Identifier: Apache-2.0

package session

import (
	"os"
	"testing"

	"github.com/boanlab/agentknox/pkg/types"
)

func newTestManager() *Manager {
	// Use a cgroup parent that almost certainly cannot be written to as an
	// unprivileged user, so placeInCgroup fails and we exercise the fallback.
	return New(nil, "agentknox-test.slice", nil)
}

func TestClassify(t *testing.T) {
	m := newTestManager()

	cases := []struct {
		name    string
		exePath string
		cmdline string
		want    types.AgentKind
	}{
		{"claude direct", "/usr/local/bin/claude", "claude\x00chat", types.AgentClaudeCode},
		{"codex direct", "/home/u/.cargo/bin/codex", "codex\x00", types.AgentCodex},
		{"crush direct", "/home/u/go/bin/crush", "crush\x00run", types.AgentCrush},
		{"claude via node wrapper", "/usr/bin/node", "node\x00/usr/lib/claude/cli.js", types.AgentClaudeCode},
		{"gemini via node wrapper", "/usr/bin/node", "node\x00/opt/node/lib/node_modules/@google/gemini-cli/bundle/gemini.js", types.AgentGemini},
		{"non-agent bash", "/bin/bash", "bash\x00-c\x00ls", types.AgentUnknown},
		{"false-positive arg", "/usr/bin/git", "git\x00commit\x00-m\x00fix claude bug", types.AgentUnknown},
		{"resolver reading binary", "/usr/bin/readelf", "readelf\x00-a\x00/usr/local/bin/claude", types.AgentUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := m.classify(tc.exePath, tc.cmdline)
			if got != tc.want {
				t.Fatalf("classify(%q, %q) = %q; want %q", tc.exePath, tc.cmdline, got, tc.want)
			}
		})
	}
}

func TestOnExecCreatesSession(t *testing.T) {
	m := newTestManager()

	ev := &types.SyscallEvent{
		Category:  types.CategoryProcess,
		Operation: "exec",
		HostPID:   424242,
		HostPPID:  1,
		CgroupID:  99887766,
		Resource:  "/usr/local/bin/claude",
	}

	var hookCalled bool
	m.OnNewSession = func(s *types.AgentSession) { hookCalled = true }

	sess, created := m.OnExec(ev)
	// A session must be created even when real cgroup placement fails (the test
	// runs unprivileged against a non-existent slice), exercising the fallback.
	if !created || sess == nil {
		t.Fatalf("OnExec did not create a session: created=%v sess=%v", created, sess)
	}
	if sess.Agent != types.AgentClaudeCode {
		t.Fatalf("Agent = %q; want %q", sess.Agent, types.AgentClaudeCode)
	}
	if sess.RootPID != ev.HostPID {
		t.Fatalf("RootPID = %d; want %d", sess.RootPID, ev.HostPID)
	}
	if sess.State != types.SessionActive {
		t.Fatalf("State = %q; want active", sess.State)
	}
	if sess.Coverage != types.CoverageNone {
		t.Fatalf("Coverage = %q; want none", sess.Coverage)
	}
	if sess.ID == "" {
		t.Fatal("session ID is empty")
	}
	if !hookCalled {
		t.Fatal("OnNewSession hook was not invoked")
	}

	// Lookup by the (fallback) event cgroup id must resolve to the session.
	if got, ok := m.LookupByCgroup(ev.CgroupID); !ok || got.ID != sess.ID {
		t.Fatalf("LookupByCgroup(%d) failed: ok=%v got=%v", ev.CgroupID, ok, got)
	}
	if len(m.List()) != 1 {
		t.Fatalf("List() len = %d; want 1", len(m.List()))
	}
}

func TestMembershipAndExit(t *testing.T) {
	m := newTestManager()

	root := &types.SyscallEvent{
		Category: types.CategoryProcess, Operation: "exec",
		HostPID: 5000, HostPPID: 1, CgroupID: 111, Resource: "/usr/bin/codex",
	}
	sess, ok := m.OnExec(root)
	if !ok {
		t.Fatal("root exec did not create a session")
	}

	// Child exec of a non-agent whose parent is the session root joins the session.
	child := &types.SyscallEvent{
		Category: types.CategoryProcess, Operation: "exec",
		HostPID: 5001, HostPPID: 5000, CgroupID: 111, Resource: "/bin/sh",
	}
	if s, created := m.OnExec(child); created || s != nil {
		t.Fatalf("child should not create a session, got created=%v", created)
	}

	// Enrich a child event -> tagged with the session.
	cev := &types.SyscallEvent{HostPID: 5001, CgroupID: 111}
	m.Enrich(cev)
	if cev.Session == nil || cev.Session.SessionID != sess.ID {
		t.Fatalf("Enrich did not tag child with session")
	}
	if cev.Meta == nil {
		t.Fatal("Enrich did not populate Meta")
	}

	// Root exit ends the session but keeps it in history/byID.
	m.OnExit(&types.SyscallEvent{HostPID: 5000})
	if _, live := m.LookupByCgroup(111); live {
		t.Fatal("cgroup should be unlinked after root exit")
	}
	found := false
	for _, s := range m.List() {
		if s.ID == sess.ID {
			found = true
			if s.State != types.SessionEnded {
				t.Fatalf("ended session state = %q", s.State)
			}
		}
	}
	if !found {
		t.Fatal("ended session missing from history")
	}
}

// TestDescendantFoldInManagedCgroup verifies that an exec inside an already-managed
// agent cgroup folds as a session member and never creates a second session, even
// when the exec'd binary itself matches an agent signature (a mis-attributed child
// exec, or a nested agent). A duplicate session on the same cgroup would, on its
// exit, tear down the live agent's cgroup enforcement, letting descendants escape
// provenance control.
func TestDescendantFoldInManagedCgroup(t *testing.T) {
	m := newTestManager()
	// Inject a managed session directly (placeInCgroup cannot run unprivileged in
	// tests, so it never sets CgroupPath via the normal path).
	sess := &types.AgentSession{
		ID: "sess-managed", Agent: types.AgentCodex, RootPID: 7000,
		CgroupID: 222, CgroupPath: "/sys/fs/cgroup/agentknox.slice/session-x",
		State: types.SessionActive, Members: []int32{7000},
	}
	m.mu.Lock()
	m.byID[sess.ID] = sess
	m.byRootPID[7000] = sess
	m.pidIndex[7000] = sess
	m.byCgroup[222] = sess
	m.mu.Unlock()

	child := &types.SyscallEvent{
		Category: types.CategoryProcess, Operation: "exec",
		HostPID: 7001, HostPPID: 7000, CgroupID: 222, Resource: "/usr/bin/codex",
	}
	got, created := m.OnExec(child)
	if created {
		t.Fatal("exec in a managed agent cgroup created a new session; want fold as member")
	}
	if got == nil || got.ID != sess.ID {
		t.Fatalf("fold returned wrong session: %v", got)
	}
	m.mu.RLock()
	_, isMember := m.pidIndex[7001]
	m.mu.RUnlock()
	if !isMember {
		t.Fatal("folded child was not registered as a session member")
	}
}

// TestCgroupHasActiveSession verifies the teardown guard: while another session is
// still active on a cgroup, ending one must report the cgroup as still occupied, so
// shared cgroup-level enforcement is not torn down under a live agent.
func TestCgroupHasActiveSession(t *testing.T) {
	m := newTestManager()
	a := &types.AgentSession{ID: "a", CgroupID: 333, State: types.SessionActive}
	b := &types.AgentSession{ID: "b", CgroupID: 333, State: types.SessionActive}
	m.mu.Lock()
	m.byID["a"], m.byID["b"] = a, b
	m.mu.Unlock()

	if !m.CgroupHasActiveSession(333, "a") {
		t.Fatal("b is active on the cgroup; guard must report it occupied")
	}
	b.State = types.SessionEnded
	if m.CgroupHasActiveSession(333, "a") {
		t.Fatal("b ended and a is excluded; cgroup must be reported free")
	}
	if !m.CgroupHasActiveSession(333, "b") {
		t.Fatal("a is still active on the cgroup; guard must report it occupied")
	}
	if m.CgroupHasActiveSession(999, "a") {
		t.Fatal("no session on cgroup 999")
	}
}

func TestSetters(t *testing.T) {
	m := newTestManager()
	ev := &types.SyscallEvent{
		Category: types.CategoryProcess, Operation: "exec",
		HostPID: 7000, CgroupID: 222, Resource: "/home/u/go/bin/crush",
	}
	sess, _ := m.OnExec(ev)

	m.SetCoverage(sess.ID, types.CoverageDegraded)
	m.MarkTampered(sess.ID)
	m.SetAttachPlan(sess.ID, &types.AttachPlan{Coverage: types.CoverageFull})

	got, _ := m.LookupByCgroup(222)
	if got.Coverage != types.CoverageFull {
		t.Fatalf("Coverage = %q; want full (plan overrides)", got.Coverage)
	}
	if !got.Tampered {
		t.Fatal("Tampered not set")
	}
	if got.AttachPlan == nil {
		t.Fatal("AttachPlan not set")
	}
}

// TestPlaceInCgroupRoot exercises real cgroup placement only when running as
// root; otherwise it is skipped.
func TestPlaceInCgroupRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for real cgroup v2 placement")
	}
	m := New(nil, "agentknox-test.slice", nil)
	// Place ourselves; guaranteed-live pid.
	_, cgid, err := m.placeInCgroup(int32(os.Getpid()), "selftest")
	if err != nil {
		t.Skipf("cgroup placement unavailable: %v", err)
	}
	if cgid == 0 {
		t.Fatal("expected non-zero cgroup id")
	}
}

// A boundary can hook cleanly and still deliver no plaintext (the rustls AEAD
// dispatch and the Node SEA case both do). Coverage must therefore be able to
// fall from full to degraded on the evidence of what actually arrived, which is
// what NoteWireIntent records — transcript-sourced intent must not count.
func TestWireIntentsDrivesCoverageDowngrade(t *testing.T) {
	m := newTestManager()
	s := &types.AgentSession{ID: "sess-wire", Coverage: types.CoverageFull}
	m.mu.Lock()
	m.byID[s.ID] = s
	m.mu.Unlock()

	// Nothing off the wire yet: this is the state that must downgrade.
	if n, ok := m.WireIntents(s.ID); !ok || n != 0 {
		t.Fatalf("fresh session: want 0 wire intents, got %d (ok=%v)", n, ok)
	}
	m.SetCoverage(s.ID, types.CoverageDegraded)
	if got := s.Coverage; got != types.CoverageDegraded {
		t.Fatalf("after downgrade: want degraded, got %q", got)
	}

	// Once live plaintext arrives, the counter must reflect it so the watchdog
	// leaves a genuinely-full session alone.
	m.NoteWireIntent(s.ID)
	m.NoteWireIntent(s.ID)
	if n, _ := m.WireIntents(s.ID); n != 2 {
		t.Fatalf("want 2 wire intents, got %d", n)
	}

	// An unknown session must report not-found rather than a bare zero, so the
	// watchdog cannot mistake it for a silent boundary and downgrade it.
	if _, ok := m.WireIntents("no-such-session"); ok {
		t.Fatal("unknown session reported as found")
	}
}
