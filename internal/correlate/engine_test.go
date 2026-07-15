// SPDX-License-Identifier: Apache-2.0

package correlate

import (
	"strings"
	"testing"
	"time"

	"github.com/boanlab/agentknox/internal/pipeline"
	"github.com/boanlab/agentknox/pkg/types"
)

// Engine must satisfy the consumer-defined Correlator contract.
var _ pipeline.Correlator = (*Engine)(nil)

// drainAction reads one CorrelatedAction or fails after a timeout.
func drainAction(t *testing.T, ch <-chan types.CorrelatedAction) types.CorrelatedAction {
	t.Helper()
	select {
	case a := <-ch:
		return a
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for CorrelatedAction")
		return types.CorrelatedAction{}
	}
}

// TestReadIntentNetworkMismatch pushes a "Read" (intent_class=read) tool_use and
// then a connect syscall in the same session and window, expecting a mismatch.
func TestReadIntentNetworkMismatch(t *testing.T) {
	e := New(nil)
	actions, edges := e.Outputs()

	now := time.Now()
	const sess = "sess-1"

	e.PushSemantic(&types.SemanticEvent{
		EventID:   "sem-1",
		Time:      now,
		SessionID: sess,
		HostPID:   1000,
		Kind:      types.SemToolUse,
		ToolUse: &types.ToolUse{
			ID:          "tu-1",
			Name:        "Read",
			IntentClass: "read",
			Input:       map[string]any{"file_path": "/home/user/notes.txt"},
		},
	})

	// Drain the tool_use edge so the buffer reflects only the effect edge next.
	select {
	case g := <-edges:
		if g.Kind != types.EdgeToolUse {
			t.Fatalf("expected tool_use edge, got %q", g.Kind)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for tool_use edge")
	}

	e.PushSyscall(&types.SyscallEvent{
		EventID:   "sys-1",
		Time:      now.Add(50 * time.Millisecond),
		HostPID:   1000,
		PID:       1000,
		Category:  types.CategoryNetwork,
		Operation: "connect",
		Resource:  "203.0.113.5:443",
		Session:   &types.SessionRef{SessionID: sess, Agent: types.AgentClaudeCode},
	})

	a := drainAction(t, actions)
	if a.ToolUseID != "tu-1" {
		t.Fatalf("expected action attributed to tu-1, got %q", a.ToolUseID)
	}
	if !a.Mismatch {
		t.Fatalf("expected Mismatch=true for read-intent + connect, got false")
	}
	if a.MismatchReason == "" {
		t.Fatalf("expected a mismatch reason")
	}
	if a.Confidence < 0.9 {
		t.Fatalf("expected high confidence for tight+lineage match, got %v", a.Confidence)
	}
	if len(a.Effects) != 1 || a.Effects[0].Category != types.CategoryNetwork {
		t.Fatalf("unexpected effects: %+v", a.Effects)
	}
	// The effect edge for the connect should also be present.
	select {
	case g := <-edges:
		if g.Kind != types.EdgeConnect {
			t.Fatalf("expected connect edge, got %q", g.Kind)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for connect edge")
	}
}

// TestSensitiveReadThenConnectTaint verifies taint propagation: a sensitive,
// user-unseen file read taints the session, and a subsequent connect inherits
// the taint labels.
func TestSensitiveReadThenConnectTaint(t *testing.T) {
	e := New(nil)
	actions, _ := e.Outputs()

	now := time.Now()
	const sess = "sess-2"

	// Sensitive read with no prior prompt/tool_use referencing the path.
	e.PushSyscall(&types.SyscallEvent{
		EventID:   "sys-read",
		Time:      now,
		PID:       2000,
		Category:  types.CategoryFile,
		Operation: "open",
		Resource:  "/home/user/.ssh/id_rsa",
		Session:   &types.SessionRef{SessionID: sess},
	})
	read := drainAction(t, actions)
	if !containsLabel(read.Taint, "user-unseen") || !containsLabel(read.Taint, "sensitive") {
		t.Fatalf("expected user-unseen+sensitive taint on read, got %v", read.Taint)
	}

	// Subsequent connect in the same session should inherit taint + data-flow.
	e.PushSyscall(&types.SyscallEvent{
		EventID:   "sys-conn",
		Time:      now.Add(100 * time.Millisecond),
		PID:       2000,
		Category:  types.CategoryNetwork,
		Operation: "connect",
		Resource:  "198.51.100.9:443",
		Session:   &types.SessionRef{SessionID: sess},
	})
	conn := drainAction(t, actions)
	if !containsLabel(conn.Taint, "data-flow") || !containsLabel(conn.Taint, "sensitive") {
		t.Fatalf("expected data-flow+sensitive taint on connect, got %v", conn.Taint)
	}
}

// TestSensitiveReadSeenInPromptNoTaint verifies that a sensitive path referenced
// in a prior prompt is NOT flagged user-unseen.
func TestSensitiveReadSeenInPromptNoTaint(t *testing.T) {
	e := New(nil)
	actions, _ := e.Outputs()

	now := time.Now()
	const sess = "sess-3"

	e.PushSemantic(&types.SemanticEvent{
		EventID:   "sem-p",
		Time:      now,
		SessionID: sess,
		Kind:      types.SemPrompt,
		Text:      "please read /home/user/.ssh/id_rsa and summarize it",
	})
	e.PushSyscall(&types.SyscallEvent{
		EventID:   "sys-read2",
		Time:      now.Add(10 * time.Millisecond),
		PID:       3000,
		Category:  types.CategoryFile,
		Operation: "open",
		Resource:  "/home/user/.ssh/id_rsa",
		Session:   &types.SessionRef{SessionID: sess},
	})
	a := drainAction(t, actions)
	if containsLabel(a.Taint, "user-unseen") {
		t.Fatalf("path referenced in prompt should not be user-unseen, got %v", a.Taint)
	}
}

// TestSystemOnlyEffectStillFlows verifies that an effect with no matching intent
// still produces a low-confidence action.
func TestSystemOnlyEffectStillFlows(t *testing.T) {
	e := New(nil)
	actions, _ := e.Outputs()

	e.PushSyscall(&types.SyscallEvent{
		EventID:   "sys-x",
		Time:      time.Now(),
		PID:       4000,
		Category:  types.CategoryProcess,
		Operation: "exec",
		Resource:  "/usr/bin/curl",
		Session:   &types.SessionRef{SessionID: "sess-4"},
	})
	a := drainAction(t, actions)
	if a.ToolUseID != "" {
		t.Fatalf("expected no intent attribution, got %q", a.ToolUseID)
	}
	if a.Confidence > 0.5 {
		t.Fatalf("expected low confidence for system-only effect, got %v", a.Confidence)
	}
}

func containsLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

func TestSensitivePathExcludesAgentSelf(t *testing.T) {
	// The agent reading its OWN provider credential to authenticate is not the
	// exfiltration of a developer secret, so it must not be tainted as sensitive.
	selfPaths := []string{
		"/home/boan/.claude/.credentials.json",
		"/home/boan/.codex/auth.json",
		"/home/boan/.gemini/gemini-credentials.json",
		"/home/boan/.config/crush/crush.json",
	}
	for _, p := range selfPaths {
		if isSensitivePath(p) {
			t.Errorf("agent-self path %q should NOT be sensitive", p)
		}
	}
	// A developer secret under the same home stays sensitive.
	devSecrets := []string{
		"/home/boan/.ssh/id_rsa", "/home/boan/.aws/credentials",
		"/home/boan/project/.env", "/home/boan/akcap/secret.txt",
	}
	for _, p := range devSecrets {
		if !isSensitivePath(p) {
			t.Errorf("developer secret %q SHOULD be sensitive", p)
		}
	}
}

// TestAgentSelfExemptionRespectsWriteProvenance covers both directions of the
// stage-and-read-back bypass: the agent's genuine provider credential file keeps
// the agent-self exemption, while a file the SESSION wrote under the same
// directory does not, so a secret staged there is still labelled sensitive.
func TestAgentSelfExemptionRespectsWriteProvenance(t *testing.T) {
	const (
		genuine = "/home/boan/.claude/.credentials.json"
		staged  = "/home/boan/.claude/aws.credentials"
	)
	s := &sessionState{}

	// Direction 1: untouched agent-self paths stay exempt.
	if sensitiveFor(s, genuine) {
		t.Errorf("untouched provider credential %q should NOT be sensitive", genuine)
	}
	if sensitiveFor(s, staged) {
		t.Errorf("agent-self path %q not written by the session should NOT be sensitive", staged)
	}

	// Direction 2: the session stages a developer secret under the same directory.
	s.noteWrite(strings.ToLower(staged))
	if !sensitiveFor(s, staged) {
		t.Errorf("session-written %q SHOULD be sensitive (exemption must not be inherited)", staged)
	}
	// The provider's own store survives a session write (an OAuth token refresh
	// rewrites it), so a refresh never severs the agent's egress to its model.
	s.noteWrite(strings.ToLower(genuine))
	if sensitiveFor(s, genuine) {
		t.Errorf("provider credential store %q must stay exempt across a token refresh", genuine)
	}
	// A path-agnostic view (no session) is unchanged: the daemon's pre-marking
	// pass must not start labelling agent-self paths.
	if isSensitivePath(staged) {
		t.Errorf("session-less check of %q must keep the agent-self exemption", staged)
	}

	// Writes outside an agent-self directory are not recorded at all, and never
	// affect a later judgement.
	s2 := &sessionState{}
	s2.noteWrite("/home/boan/project/.env")
	if len(s2.wroteSelf) != 0 {
		t.Errorf("writes outside an agent-self directory must not be recorded, got %v", s2.wroteSelf)
	}

	// Once the record is capped, the exemption is withheld rather than granted on
	// evidence the session can no longer hold; the provider store is still exempt.
	s3 := &sessionState{wroteSelfFull: true}
	if !sensitiveFor(s3, staged) {
		t.Errorf("with a capped write record, %q should NOT keep the exemption", staged)
	}
	if sensitiveFor(s3, genuine) {
		t.Errorf("with a capped write record, provider store %q should stay exempt", genuine)
	}
}

// TestStagedSecretReadBackTaintsSession drives the bypass end-to-end through the
// engine: the session writes a secret into the agent's own config directory and
// reads it back, and the read must still taint the session so a following connect
// carries the data-flow label (which is what arms deny-egress).
func TestStagedSecretReadBackTaintsSession(t *testing.T) {
	e := New(nil)
	actions, _ := e.Outputs()
	now := time.Now()
	const sess = "sess-stage"
	const staged = "/home/boan/.claude/aws.credentials"

	e.PushSyscall(&types.SyscallEvent{
		EventID: "sys-w", Time: now, PID: 700, HostPID: 700,
		Category: types.CategoryFile, Operation: "write", Resource: staged,
		Session: &types.SessionRef{SessionID: sess, Agent: types.AgentClaudeCode},
	})
	drainAction(t, actions)

	e.PushSyscall(&types.SyscallEvent{
		EventID: "sys-r", Time: now.Add(10 * time.Millisecond), PID: 700, HostPID: 700,
		Category: types.CategoryFile, Operation: "read", Resource: staged,
		Session: &types.SessionRef{SessionID: sess, Agent: types.AgentClaudeCode},
	})
	read := drainAction(t, actions)
	if !containsLabel(read.Taint, "sensitive") {
		t.Fatalf("read-back of a session-staged secret should be sensitive, got %v", read.Taint)
	}

	e.PushSyscall(&types.SyscallEvent{
		EventID: "sys-c", Time: now.Add(20 * time.Millisecond), PID: 700, HostPID: 700,
		Category: types.CategoryNetwork, Operation: "connect", Resource: "203.0.113.9:443",
		Session: &types.SessionRef{SessionID: sess, Agent: types.AgentClaudeCode},
	})
	conn := drainAction(t, actions)
	if !containsLabel(conn.Taint, "data-flow") {
		t.Fatalf("connect after the staged read-back should carry data-flow, got %v", conn.Taint)
	}
}

// TestAgentOwnCredentialReadStaysUntainted is the false-positive guard for the
// test above: an agent that refreshes and re-reads its own credential store must
// not taint the session, or enforcement would sever its connection to its model.
func TestAgentOwnCredentialReadStaysUntainted(t *testing.T) {
	e := New(nil)
	actions, _ := e.Outputs()
	now := time.Now()
	const sess = "sess-refresh"
	const cred = "/home/boan/.claude/.credentials.json"

	e.PushSyscall(&types.SyscallEvent{
		EventID: "sys-w", Time: now, PID: 800, HostPID: 800,
		Category: types.CategoryFile, Operation: "write", Resource: cred,
		Session: &types.SessionRef{SessionID: sess, Agent: types.AgentClaudeCode},
	})
	drainAction(t, actions)

	e.PushSyscall(&types.SyscallEvent{
		EventID: "sys-r", Time: now.Add(10 * time.Millisecond), PID: 800, HostPID: 800,
		Category: types.CategoryFile, Operation: "read", Resource: cred,
		Session: &types.SessionRef{SessionID: sess, Agent: types.AgentClaudeCode},
	})
	read := drainAction(t, actions)
	if len(read.Taint) != 0 {
		t.Fatalf("re-reading the agent's own refreshed credential store must not taint, got %v", read.Taint)
	}
}
