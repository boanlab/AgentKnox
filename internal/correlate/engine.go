// SPDX-License-Identifier: Apache-2.0

// Package correlate implements the Correlation Engine. It fuses
// semantic intents (tool_use) with system effects (exec/open/connect) causally,
// propagates a simplified in-process taint, and detects intent-effect mismatch.
//
// The engine is fed by PushSemantic and PushSyscall. It emits two output
// streams: CorrelatedAction (fused intent+effect analysis) and GraphEdge (typed
// causal-graph edges) on the channels returned by Outputs. Emission is
// non-blocking: if an output channel is full the item is dropped and logged, so
// a slow consumer can never stall the ingest path.
//
// The implementation is synchronous and starts no background goroutines.
package correlate

import (
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/boanlab/agentknox/pkg/types"
)

const (
	// intentWindow is the sliding window during which a pending tool_use intent
	// remains eligible to claim a system effect in the same session.
	intentWindow = 5 * time.Second
	// tightWindow is the proximity under which a matched effect is treated as
	// high-confidence (same tool call, essentially immediate).
	tightWindow = 200 * time.Millisecond
	// promptIndexCap bounds the per-session recent-text index used to decide
	// whether a touched resource was "seen" by the user/model.
	promptIndexCap = 128
	// outputBuffer is the capacity of each output channel.
	outputBuffer = 4096
)

// sensitivePatterns are lowercase substrings that mark a file resource as
// sensitive for taint purposes.
var sensitivePatterns = []string{
	"/.ssh", ".env", "/.aws", "credentials", "id_rsa", "id_ed25519",
	"token", ".pem", "secret", "/.netrc", ".kube/config",
}

// agentSelfPatterns are lowercase substrings identifying an agent's own provider
// config/credential store. Reads here are excluded from sensitive-path taint,
// since they are normal auth to the agent's own model rather than secret
// exfiltration. A developer credential under the same home (e.g.
// /.aws/credentials) is not listed here and stays tainted.
//
// The exemption covers the store as the vendor installs it, not whatever the
// session puts there: a file the session itself wrote under one of these
// directories does NOT inherit it (see sensitiveFor), so staging a secret into
// the agent's own config directory and reading it back does not launder away the
// sensitive label.
var agentSelfPatterns = []string{
	"/.claude/", "/.codex/", "/.gemini/", "/.config/crush",
	"/.config/gcloud", "/.config/gemini",
	"/.crush/", "/.local/share/crush", "/.copilot/", "/.config/github-copilot",
}

// providerCredentialFiles are the exact basenames of the provider credential
// stores the agents themselves rewrite in the course of normal operation (an
// OAuth refresh writes the file and then reads it back). Only these keep the
// agent-self exemption across a session write: without the carve-out a token
// refresh would label the agent's own credential file sensitive and sever the
// session's egress to its own model. The match is on the whole basename, so a
// staged secret under a name of the attacker's choosing (".claude/credentials",
// ".claude/.aws/credentials", ".claude/x.pem") does not reach it.
var providerCredentialFiles = map[string]struct{}{
	".credentials.json":                    {}, // Claude Code
	"auth.json":                            {}, // Codex
	"oauth_creds.json":                     {}, // Gemini CLI
	"application_default_credentials.json": {}, // gcloud ADC
	"credentials.db":                       {}, // gcloud
	"access_tokens.db":                     {}, // gcloud
	"hosts.json":                           {}, // GitHub Copilot
	"apps.json":                            {}, // GitHub Copilot
}

// writtenPathCap bounds the per-session record of agent-self paths the session
// wrote. Only writes under agentSelfPatterns are recorded (nothing else consults
// the record), so the cap is far out of reach in practice; past it the session
// stops granting the exemption at all rather than granting it on missing
// evidence.
const writtenPathCap = 4096

// publicPathPrefixes are system locations holding world-readable public material
// (chiefly the CA trust store used for TLS). These match the `.pem` sensitive
// pattern but are not developer secrets; tainting them would pre-arm deny-egress
// and sever the agent's own model connection, so reads here are never sensitive.
var publicPathPrefixes = []string{
	"/etc/ssl/", "/usr/share/ca-certificates/", "/etc/pki/",
	"/etc/ca-certificates/", "/usr/lib/ssl/", "/usr/local/share/ca-certificates/",
}

// systemCodePrefixes are read-only system code/library trees. Files here are never
// developer secrets; excluding them avoids false-positive taint (e.g. "token"
// matching python's tokenize .pyc under /usr/lib), which would otherwise sever a
// python-using agent's egress on a benign stdlib import.
var systemCodePrefixes = []string{
	"/usr/lib/", "/usr/share/", "/usr/local/lib/", "/usr/local/share/",
	"/lib/", "/lib64/", "/opt/", "/snap/", "/nix/",
}

// isSystemCodePath reports whether a lowercased path is system code or an
// interpreter/package cache (never a developer secret).
func isSystemCodePath(lp string) bool {
	if strings.HasSuffix(lp, ".pyc") || strings.HasSuffix(lp, ".pyo") ||
		strings.Contains(lp, "/__pycache__/") || strings.Contains(lp, "/site-packages/") ||
		strings.Contains(lp, "/node_modules/") {
		return true
	}
	for _, pre := range systemCodePrefixes {
		if strings.HasPrefix(lp, pre) {
			return true
		}
	}
	return false
}

// pendingIntent is a recorded tool_use awaiting attribution of system effects.
type pendingIntent struct {
	tool types.ToolUse
	at   time.Time
	pid  int32 // host pid that requested the tool (best effort)
}

// sessionState is the per-session correlation state, guarded by Engine.mu.
type sessionState struct {
	intents     []pendingIntent
	promptIndex []string // lowercased recent prompt / tool_use input text
	tainted     bool     // a sensitive, user-unseen read has occurred
	taintLabels []string // labels to propagate to downstream effects

	// wroteSelf records the lowercased paths under an agent-self directory that
	// this session wrote (write provenance). A read of one of them is judged on
	// its own name rather than on the directory's exemption. wroteSelfFull marks
	// the record as capped: the exemption is then withheld rather than granted on
	// evidence the session can no longer hold.
	wroteSelf     map[string]struct{}
	wroteSelfFull bool
}

// noteWrite records a session write under an agent-self directory. Writes
// elsewhere are not recorded: the record exists only to decide whether the
// agent-self exemption still applies.
func (s *sessionState) noteWrite(lp string) {
	if !isAgentSelfPath(lp) {
		return
	}
	if s.wroteSelf == nil {
		s.wroteSelf = make(map[string]struct{})
	}
	if _, ok := s.wroteSelf[lp]; ok {
		return
	}
	if len(s.wroteSelf) >= writtenPathCap {
		s.wroteSelfFull = true
		return
	}
	s.wroteSelf[lp] = struct{}{}
}

// wroteAgentSelf reports whether this session's own writes disqualify lp from the
// agent-self exemption. A provider credential store the agent rewrites during a
// normal token refresh keeps the exemption; anything else the session wrote there
// loses it.
func (s *sessionState) wroteAgentSelf(lp string) bool {
	if s == nil {
		return false
	}
	if isProviderCredentialFile(lp) {
		return false
	}
	if s.wroteSelfFull {
		return true
	}
	_, ok := s.wroteSelf[lp]
	return ok
}

// isProviderCredentialFile reports whether a lowercased path names a provider's
// own credential store by basename.
func isProviderCredentialFile(lp string) bool {
	base := lp
	if i := strings.LastIndex(lp, "/"); i >= 0 {
		base = lp[i+1:]
	}
	_, ok := providerCredentialFiles[base]
	return ok
}

// Engine is the correlation engine. It implements pipeline.Correlator.
type Engine struct {
	log *zap.Logger

	mu       sync.Mutex
	sessions map[string]*sessionState

	// globalIndex is an agent-wide recent-prompt/tool-text index, consulted in
	// addition to the per-session index: a single agent invocation can fan out
	// into many signature-matched processes tracked as separate sessions, so a
	// file named in the prompt must be recognized regardless of which session
	// reads it. Guarded by mu.
	globalIndex []string

	actions chan types.CorrelatedAction
	edges   chan types.GraphEdge
}

// New constructs an Engine with buffered output channels. The logger may be nil.
func New(log *zap.Logger) *Engine {
	if log == nil {
		log = zap.NewNop()
	}
	return &Engine{
		log:      log,
		sessions: make(map[string]*sessionState),
		actions:  make(chan types.CorrelatedAction, outputBuffer),
		edges:    make(chan types.GraphEdge, outputBuffer),
	}
}

// Outputs returns the correlated-action and graph-edge streams. The same
// channels are returned on every call.
func (e *Engine) Outputs() (<-chan types.CorrelatedAction, <-chan types.GraphEdge) {
	return e.actions, e.edges
}

// state returns (creating if needed) the mutable state for a session id. The
// caller must hold e.mu.
func (e *Engine) state(sessionID string) *sessionState {
	s := e.sessions[sessionID]
	if s == nil {
		s = &sessionState{}
		e.sessions[sessionID] = s
	}
	return s
}

// PushSemantic ingests a semantic event. tool_use events register a pending
// intent; any text-bearing event feeds the recent-prompt index used by taint.
func (e *Engine) PushSemantic(ev *types.SemanticEvent) {
	if ev == nil {
		return
	}
	when := eventTime(ev.Time, ev.TimestampNS)

	// Emit a graph edge for the tool_use intent itself.
	if ev.Kind == types.SemToolUse && ev.ToolUse != nil {
		res := ev.ToolUse.Name
		e.emitEdge(types.GraphEdge{
			SessionID: ev.SessionID,
			Kind:      types.EdgeToolUse,
			Time:      when,
			SrcPID:    ev.HostPID,
			Resource:  res,
			RefEvent:  ev.EventID,
		})
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.state(ev.SessionID)

	switch ev.Kind {
	case types.SemToolUse:
		if ev.ToolUse != nil {
			s.intents = append(s.intents, pendingIntent{
				tool: *ev.ToolUse,
				at:   when,
				pid:  ev.HostPID,
			})
			e.pruneIntents(s, when)
			// A tool_use name/input is the model's decision (possibly injection-
			// driven), not a user reference, so it must not feed the "seen" index;
			// otherwise the model naming its own read target would suppress that
			// read's exfil-taint.
		}
	case types.SemPrompt:
		// Only the user's prompt marks a resource as user-referenced. Assistant
		// text and tool results (e.g. an injected NOTES.md naming the exfil
		// target) are adversary-controllable and must not populate the seen
		// index, or an indirect-injection exfil target would be treated as
		// already-referenced and never tainted.
		s.indexText(ev.Text)
		e.indexGlobal(ev.Text)
	}
}

// indexGlobal appends text to the agent-wide index, bounded like the per-session
// index. Caller holds e.mu.
func (e *Engine) indexGlobal(t string) {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" {
		return
	}
	e.globalIndex = append(e.globalIndex, t)
	if len(e.globalIndex) > promptIndexCap {
		e.globalIndex = e.globalIndex[len(e.globalIndex)-promptIndexCap:]
	}
}

// PushSyscall ingests a system event, emits its raw graph edge, and produces a
// CorrelatedAction attributing the effect to a recent tool_use intent (if any)
// with taint and intent-effect mismatch analysis.
func (e *Engine) PushSyscall(ev *types.SyscallEvent) {
	if ev == nil {
		return
	}
	kind, ok := edgeKindFor(ev)
	if !ok {
		return // not an effect we model (e.g. capability/ipc): no edge/action
	}
	when := eventTime(ev.Time, ev.TimestampNS)

	sessionID := ""
	if ev.Session != nil {
		sessionID = ev.Session.SessionID
	}

	// Raw effect edge is always emitted, even for session-less events.
	e.emitEdge(types.GraphEdge{
		SessionID: sessionID,
		Kind:      kind,
		Time:      when,
		SrcPID:    ev.PID,
		Resource:  ev.Resource,
		RefEvent:  ev.EventID,
	})

	eff := types.Effect{
		Category:  ev.Category,
		Operation: ev.Operation,
		Resource:  ev.Resource,
		EventID:   ev.EventID,
	}

	action := types.CorrelatedAction{
		ActionID:  newID(),
		SessionID: sessionID,
		HostPID:   ev.HostPID,
		Time:      when,
		Effects:   []types.Effect{eff},
	}

	e.mu.Lock()
	var s *sessionState
	if sessionID != "" {
		s = e.state(sessionID)
	}

	// Attribute to the most recent in-window pending intent for this session.
	var matched *pendingIntent
	if s != nil {
		e.pruneIntents(s, when)
		matched = latestIntent(s, when)
	}

	if matched != nil {
		action.ToolUseID = matched.tool.ID
		action.ToolName = matched.tool.Name
		action.IntentClass = matched.tool.IntentClass
		action.Confidence = confidence(matched, ev, when)
		if reason, bad := mismatch(matched.tool.IntentClass, ev); bad {
			action.Mismatch = true
			action.MismatchReason = reason
		}
	} else {
		// System-only effect: still flows, low confidence, no intent.
		action.Confidence = 0.3
	}

	// Taint analysis (mutates session taint state).
	if s != nil {
		e.applyTaint(s, ev, &action)
	}
	e.mu.Unlock()

	e.emitAction(action)
}

// applyTaint applies the simplified in-process taint heuristic. The caller must
// hold e.mu.
func (e *Engine) applyTaint(s *sessionState, ev *types.SyscallEvent, a *types.CorrelatedAction) {
	switch ev.Category {
	case types.CategoryFile:
		// A read/open of a sensitive path the user/model never referenced taints
		// the session. Requires an absolute, resolved path: skip a bare relative
		// path (an unresolved probe like a ".env" the agent attempts in its CWD,
		// which may not even exist), since tainting it would arm deny-egress and
		// sever the agent's own model connection. Real secrets resolve to
		// absolute paths and still taint.
		// Write provenance first: a file this session wrote under the agent's own
		// config directory no longer inherits that directory's exemption, so a
		// staged copy is read back as what it is.
		if isWriteLike(ev.Operation) && strings.HasPrefix(ev.Resource, "/") {
			s.noteWrite(strings.ToLower(ev.Resource))
		}
		if isReadLike(ev.Operation) && strings.HasPrefix(ev.Resource, "/") &&
			sensitiveFor(s, ev.Resource) {
			seen := s.seen(ev.Resource) || indexHasResource(e.globalIndex, ev.Resource)
			e.log.Debug("taint: sensitive read",
				zap.String("resource", ev.Resource), zap.Bool("seen", seen),
				zap.Int("prompt_index", len(s.promptIndex)), zap.Int("global_index", len(e.globalIndex)))
			if !seen {
				labels := []string{"user-unseen", "sensitive"}
				a.Taint = mergeLabels(a.Taint, labels)
				s.tainted = true
				s.taintLabels = mergeLabels(s.taintLabels, labels)
			}
		}
	case types.CategoryNetwork, types.CategoryDNS:
		// A connect after a tainted read is a data-flow (exfiltration) suspect.
		if s.tainted {
			a.Taint = mergeLabels(a.Taint, s.taintLabels)
			a.Taint = mergeLabels(a.Taint, []string{"data-flow"})
		}
	}
}

// pruneIntents drops intents older than the sliding window. Caller holds e.mu.
func (e *Engine) pruneIntents(s *sessionState, now time.Time) {
	cut := now.Add(-intentWindow)
	i := 0
	for _, in := range s.intents {
		if in.at.After(cut) {
			s.intents[i] = in
			i++
		}
	}
	s.intents = s.intents[:i]
}

// --- helpers ---------------------------------------------------------------

func (e *Engine) emitAction(a types.CorrelatedAction) {
	select {
	case e.actions <- a:
	default:
		e.log.Warn("correlate: action channel full, dropping",
			zap.String("session", a.SessionID), zap.String("action", a.ActionID))
	}
}

func (e *Engine) emitEdge(g types.GraphEdge) {
	select {
	case e.edges <- g:
	default:
		e.log.Warn("correlate: edge channel full, dropping",
			zap.String("session", g.SessionID), zap.String("kind", string(g.Kind)))
	}
}

func (s *sessionState) indexText(t string) {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" {
		return
	}
	s.promptIndex = append(s.promptIndex, t)
	if len(s.promptIndex) > promptIndexCap {
		s.promptIndex = s.promptIndex[len(s.promptIndex)-promptIndexCap:]
	}
}

// seen reports whether the resource (or its basename) appeared in any recent
// prompt/tool_use text for the session.
func (s *sessionState) seen(resource string) bool {
	return indexHasResource(s.promptIndex, resource)
}

// indexHasResource reports whether a resource path (or its basename) appears in
// any of the indexed recent prompt/tool text.
func indexHasResource(index []string, resource string) bool {
	r := strings.ToLower(strings.TrimSpace(resource))
	if r == "" {
		return false
	}
	base := r
	if i := strings.LastIndexByte(r, '/'); i >= 0 && i+1 < len(r) {
		base = r[i+1:]
	}
	for _, txt := range index {
		if strings.Contains(txt, r) || (base != "" && strings.Contains(txt, base)) {
			return true
		}
	}
	return false
}

// latestIntent returns the most recent in-window pending intent, or nil.
func latestIntent(s *sessionState, now time.Time) *pendingIntent {
	cut := now.Add(-intentWindow)
	for i := len(s.intents) - 1; i >= 0; i-- {
		if s.intents[i].at.After(cut) {
			return &s.intents[i]
		}
	}
	return nil
}

// confidence scores an intent↔effect match by time proximity and pid lineage.
func confidence(in *pendingIntent, ev *types.SyscallEvent, when time.Time) float64 {
	dt := when.Sub(in.at)
	if dt < 0 {
		dt = -dt
	}
	lineage := in.pid != 0 &&
		(ev.HostPID == in.pid || ev.HostPPID == in.pid || ev.PID == in.pid || ev.PPID == in.pid)
	if dt <= tightWindow {
		if lineage {
			return 1.0
		}
		return 0.9
	}
	// Loose match: scale 0.8 → 0.6 across the remaining window.
	frac := float64(dt-tightWindow) / float64(intentWindow-tightWindow)
	conf := 0.8 - 0.2*frac
	if conf < 0.6 {
		conf = 0.6
	}
	if lineage {
		conf += 0.05
		if conf > 0.85 {
			conf = 0.85
		}
	}
	return conf
}

// mismatch applies the intent-effect divergence rules. It returns a reason and
// true when the declared intent class conflicts with the observed effect.
func mismatch(intentClass string, ev *types.SyscallEvent) (string, bool) {
	switch strings.ToLower(intentClass) {
	case "read":
		switch ev.Category {
		case types.CategoryNetwork, types.CategoryDNS:
			return "read-only intent produced a network connect", true
		case types.CategoryFile:
			if isWriteLike(ev.Operation) {
				return "read-only intent produced a file write", true
			}
		case types.CategoryProcess:
			if isExecLike(ev.Operation) {
				return "read-only intent spawned a process (exec)", true
			}
		}
	case "write":
		switch ev.Category {
		case types.CategoryNetwork, types.CategoryDNS:
			return "write intent produced a network connect", true
		case types.CategoryProcess:
			if isExecLike(ev.Operation) {
				return "write intent spawned a process (exec)", true
			}
		}
	case "network":
		if ev.Category == types.CategoryProcess && isExecLike(ev.Operation) {
			return "network intent spawned a process (exec)", true
		}
	}
	return "", false
}

// edgeKindFor maps a system event to its typed graph edge. ok=false means the
// event is not a modeled effect and should produce neither edge nor action.
func edgeKindFor(ev *types.SyscallEvent) (types.EdgeKind, bool) {
	switch ev.Category {
	case types.CategoryProcess:
		if ev.Operation == "fork" || ev.Operation == "clone" || ev.Operation == "clone3" {
			return types.EdgeFork, true
		}
		return types.EdgeExec, true
	case types.CategoryFile:
		return types.EdgeFileTouch, true
	case types.CategoryNetwork:
		return types.EdgeConnect, true
	case types.CategoryDNS:
		return types.EdgeDNS, true
	case types.CategoryDatabase:
		return types.EdgeDBQuery, true
	default:
		return "", false
	}
}

// IsSensitiveSource reports whether an absolute path is a developer secret that must
// not be exfiltrated (matches a sensitive pattern, excluding public CA material and
// the agent's own provider config). Exported so the daemon can pre-mark these paths
// for the in-kernel synchronous read-taint egress arm.
func IsSensitiveSource(p string) bool { return isSensitivePath(p) }

// isSensitivePath reports whether a file resource matches a sensitive pattern and is
// neither public CA material, system code, nor the agent's own provider
// configuration/credential store (which the agent reads to authenticate to its model
// in the course of normal operation). It judges the path alone, with no session
// context; the daemon uses it to pre-mark secrets in the kernel before any session
// runs.
func isSensitivePath(p string) bool { return sensitiveFor(nil, p) }

// sensitiveFor is isSensitivePath with the session's write provenance consulted.
// The agent-self exemption covers the provider store as installed, not a file the
// session staged there: without this, copying a developer secret into the agent's
// own config directory and reading it back would strip the sensitive label and
// leave deny-egress unarmed. Provenance here is the session's observed
// write-opens; a rename reports only its source path, so a secret MOVED into the
// directory under a name that no sensitive pattern matches is still outside this
// label (the kernel's own inode/path taint is what follows that file for
// execution provenance).
func sensitiveFor(s *sessionState, p string) bool {
	lp := strings.ToLower(p)
	if isAgentSelfPath(lp) && !s.wroteAgentSelf(lp) {
		return false
	}
	for _, pre := range publicPathPrefixes {
		if strings.HasPrefix(lp, pre) {
			return false
		}
	}
	if isSystemCodePath(lp) {
		return false
	}
	for _, pat := range sensitivePatterns {
		if strings.Contains(lp, pat) {
			return true
		}
	}
	return false
}

// isAgentSelfPath reports whether a lowercased path is under an agent's own
// provider config/credential directory. Such a path is excluded from sensitive
// taint unless the session wrote it (sensitiveFor).
func isAgentSelfPath(lp string) bool {
	for _, pat := range agentSelfPatterns {
		if strings.Contains(lp, pat) {
			return true
		}
	}
	return false
}

func isReadLike(op string) bool {
	switch strings.ToLower(op) {
	case "read", "open", "openat", "readv", "pread", "stat", "lstat":
		return true
	}
	return false
}

func isWriteLike(op string) bool {
	switch strings.ToLower(op) {
	case "write", "writev", "pwrite", "truncate", "unlink", "rename",
		"chmod", "chown", "mkdir", "create", "creat":
		return true
	}
	return false
}

func isExecLike(op string) bool {
	switch strings.ToLower(op) {
	case "exec", "execve", "execveat":
		return true
	}
	return false
}

// mergeLabels appends src labels to dst, de-duplicating.
func mergeLabels(dst, src []string) []string {
	for _, l := range src {
		found := false
		for _, d := range dst {
			if d == l {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, l)
		}
	}
	return dst
}

// eventTime prefers the wall-clock Time; if zero it derives from the ns stamp.
func eventTime(t time.Time, ns uint64) time.Time {
	if !t.IsZero() {
		return t
	}
	if ns != 0 {
		return time.Unix(0, int64(ns))
	}
	return time.Now()
}

func newID() string { return types.NewEventID() }
