// SPDX-License-Identifier: Apache-2.0

// Package session implements the Session Manager & Agent Adapter.
//
// The supported coding agents (Claude Code, Codex CLI, Crush, Gemini CLI) are
// detected from their exec events and normalized into a single
// types.AgentSession that scopes monitoring and enriches downstream events with
// session/host identity. Detection is transparent: the agents are not
// modified. By default their processes are left in place and scoped by pid
// tree; setting ManageCgroup instead moves the process tree into a dedicated
// cgroup.
//
// The manager is consumer-defined against the pipeline.SessionManager interface
// and depends only on pkg/types so it can be built in isolation.
package session

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/boanlab/agentknox/pkg/types"
)

// defaultSignatures are the binary basenames matched during agent detection.
// Kept conservative to avoid false positives (e.g. an editor or resolver that
// merely opens/reads one of these binaries is not an agent exec).
var defaultSignatures = []string{"claude", "codex", "crush", "gemini", "copilot"}

// cgroupRoot is the cgroup v2 unified hierarchy mount point on Linux.
// cgroupRoot is a var, not a const, so tests can point the managed subtree at a
// temporary directory instead of the real cgroup2 mount.
var cgroupRoot = "/sys/fs/cgroup"

// Manager detects agents, normalizes them into AgentSession, places them into a
// managed cgroup, tracks membership/lifecycle, and enriches events. All state is
// guarded by mu.
type Manager struct {
	log          *zap.Logger
	signatures   []string
	cgroupParent string // e.g. "agentknox.slice"
	nodeName     string

	// OnNewSession, if set, runs outside the lock when a session is created:
	// resolver attach + sensor registration.
	OnNewSession func(*types.AgentSession)

	// OnSessionEnded, if set, runs outside the lock when a session's root exits:
	// sensor unregister + per-session cleanup.
	OnSessionEnded func(*types.AgentSession)

	// OnMemberExit, if set, runs outside the lock when a NON-root member of a
	// session exits, so the caller can release the per-pid kernel state it
	// registered for that process.
	//
	// Session teardown cannot cover this: it walks sess.Members, from which an
	// already-exited child has been removed by the time the root exits, so every
	// bash, git and node the agent ever spawned left a permanent entry in a
	// 65536-slot map. Once that map is full, registration and enforcement start
	// failing and newly spawned processes are neither observed nor enforced.
	OnMemberExit func(sess *types.AgentSession, pid int32)

	// ManageCgroup controls whether a detected agent's process tree is moved into
	// a dedicated managed cgroup (dedicated enforcement key, but invasive to live
	// processes) or left in place, using its existing cgroup id as the key
	// (non-invasive default).
	ManageCgroup bool

	mu         sync.RWMutex
	byID       map[string]*types.AgentSession // session id  -> session
	byCgroup   map[uint64]*types.AgentSession // cgroup id   -> session
	byRootPID  map[int32]*types.AgentSession  // root host pid -> session
	pidIndex   map[int32]*types.AgentSession  // any member host pid -> session
	history    []*types.AgentSession          // recently ended sessions
	historyMax int
}

// New constructs a Manager. signatures may be nil, in which case the default set
// (claude, codex, crush, gemini) is used. cgroupParent is the managed slice under the
// cgroup v2 root (e.g. "agentknox.slice").
func New(signatures []string, cgroupParent string, log *zap.Logger) *Manager {
	if log == nil {
		log = zap.NewNop()
	}
	sigs := signatures
	if len(sigs) == 0 {
		sigs = append([]string(nil), defaultSignatures...)
	}
	if cgroupParent == "" {
		cgroupParent = "agentknox.slice"
	}
	host, err := os.Hostname()
	if err != nil {
		host = ""
	}
	return &Manager{
		log:          log,
		signatures:   sigs,
		cgroupParent: cgroupParent,
		nodeName:     host,
		byID:         make(map[string]*types.AgentSession),
		byCgroup:     make(map[uint64]*types.AgentSession),
		byRootPID:    make(map[int32]*types.AgentSession),
		pidIndex:     make(map[int32]*types.AgentSession),
		historyMax:   256,
	}
}

// classify maps an exec'd binary path plus its /proc cmdline to an AgentKind.
// It uses conservative basename + token matching: the leading argv token (the
// program name) must itself match a signature. This avoids classifying a process
// that merely mentions "claude" in a later argument (e.g. a resolver reading the
// binary, or `git commit -m "fix claude"`).
func (m *Manager) classify(exePath, cmdline string) types.AgentKind {
	// Candidate names: the exe basename and the first cmdline token's basename.
	var candidates []string
	if exePath != "" {
		candidates = append(candidates, filepath.Base(exePath))
	}
	// cmdline is NUL-separated on Linux; tokenize on both NUL and space so the
	// helper also works with a plain space-joined command line (tests).
	tokens := splitCmdline(cmdline)
	if len(tokens) > 0 {
		candidates = append(candidates, filepath.Base(tokens[0]))
	}

	for _, c := range candidates {
		name := strings.ToLower(strings.TrimSpace(c))
		// Handle a common interpreter wrapper: `node /path/to/claude/cli.js`.
		// When the program is a runtime, the basename (e.g. "cli.js") won't match,
		// so scan the script argument's PATH COMPONENTS for an exact signature
		// match (e.g. ".../claude-code/cli.js" -> "claude-code"). Exact-only here,
		// not prefix, to stay conservative against dirs like "claude-notes".
		switch name {
		case "node", "nodejs", "bun", "deno", "python", "python3":
			if len(tokens) > 1 {
				if kind := matchPathComponents(tokens[1], m.signatures); kind != types.AgentUnknown {
					return kind
				}
			}
			continue
		}
		if kind := matchSignature(name, m.signatures); kind != types.AgentUnknown {
			return kind
		}
	}
	return types.AgentUnknown
}

// matchPathComponents reports the AgentKind if any path component of p exactly
// equals a signature (or a "<sig>.js" variant of it).
func matchPathComponents(p string, signatures []string) types.AgentKind {
	for _, comp := range strings.Split(p, "/") {
		comp = strings.ToLower(strings.TrimSpace(comp))
		if comp == "" {
			continue
		}
		comp = strings.TrimSuffix(comp, ".js")
		for _, sig := range signatures {
			sig = strings.ToLower(strings.TrimSpace(sig))
			if sig != "" && comp == sig {
				return signatureToKind(sig)
			}
		}
	}
	return types.AgentUnknown
}

// matchSignature reports the AgentKind for a basename if it matches one of the
// configured signatures (exact, or as a "name.js"/versioned variant).
func matchSignature(name string, signatures []string) types.AgentKind {
	for _, sig := range signatures {
		sig = strings.ToLower(strings.TrimSpace(sig))
		if sig == "" {
			continue
		}
		if name == sig || strings.HasPrefix(name, sig+".") || strings.HasPrefix(name, sig+"-") {
			return signatureToKind(sig)
		}
	}
	return types.AgentUnknown
}

// signatureToKind maps a raw signature token to the normalized AgentKind.
func signatureToKind(sig string) types.AgentKind {
	switch sig {
	case "claude", "claude-code":
		return types.AgentClaudeCode
	case "codex":
		return types.AgentCodex
	case "crush":
		return types.AgentCrush
	case "gemini":
		return types.AgentGemini
	case "copilot":
		return types.AgentCopilot
	default:
		return types.AgentUnknown
	}
}

// splitCmdline tokenizes a /proc/<pid>/cmdline value (NUL-separated) or a plain
// space-joined command line into non-empty tokens.
func splitCmdline(cmdline string) []string {
	fields := strings.FieldsFunc(cmdline, func(r rune) bool {
		return r == '\x00' || r == ' ' || r == '\t' || r == '\n'
	})
	return fields
}

// AgentOf classifies a live process by its executable and command line and
// returns the agent kind (AgentUnknown if it is not a supported agent). The
// daemon uses this to decide whether a session member that execs a distinct
// binary is itself an agent worker needing its own semantic resolve+attach
// (e.g. Copilot's native worker binary, spawned by its Node launcher).
func (m *Manager) AgentOf(pid int32) types.AgentKind {
	exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	return m.classify(exe, readCmdline(pid))
}

// readCmdline reads /proc/<pid>/cmdline, best-effort.
func readCmdline(pid int32) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return string(b)
}

// OnExec inspects an exec event. If it is a supported agent's exec (and not yet
// tracked), a new session is created and (session, true) is returned. For a
// non-agent exec whose parent already belongs to a session, the pid is added to
// that session's membership and (session, false) is returned.
func (m *Manager) OnExec(ev *types.SyscallEvent) (*types.AgentSession, bool) {
	if ev == nil {
		return nil, false
	}
	if ev.Category != types.CategoryProcess || ev.Operation != "exec" {
		return nil, false
	}

	// Self-exclusion: never onboard the AgentKnox process itself.
	if ev.HostPID == int32(os.Getpid()) {
		return nil, false
	}

	// Descendant fold: an exec inside an already-managed agent cgroup belongs to
	// that agent's process tree (a child shell, tool, or interpreter), never a new
	// agent root. Fold it as a member before classification, so a child binary that
	// happens to match a signature (or a mis-attributed exec whose Resource fell
	// back to the agent's ExePath) cannot spawn a duplicate session on the same
	// cgroup; that duplicate's later exit would delete the shared cgroup's
	// enforcement (ak_sessions[cgid]) out from under the still-live agent.
	// Restricted to managed, dedicated cgroups (CgroupPath set and the exec's
	// cgroup equal to the session's managed cgroup id) so a shared login cgroup
	// (manageCgroup=false) never swallows unrelated processes.
	if ev.CgroupID != 0 {
		m.mu.Lock()
		if s, ok := m.byCgroup[ev.CgroupID]; ok && s.State == types.SessionActive &&
			s.CgroupPath != "" && ev.CgroupID == s.CgroupID {
			m.addMemberLocked(s, ev.HostPID)
			m.mu.Unlock()
			return s, false
		}
		m.mu.Unlock()
	}

	// Prefer the exec'd binary path; fall back to the recorded ExePath.
	exePath := ev.Resource
	if exePath == "" {
		exePath = ev.ExePath
	}
	cmdline := readCmdline(ev.HostPID)

	kind := m.classify(exePath, cmdline)
	if kind != types.AgentUnknown {
		return m.createSession(ev, kind, exePath)
	}

	// Not an agent: fold into an existing session if the parent is a member.
	m.mu.Lock()
	parent := m.pidIndex[ev.HostPPID]
	if parent != nil && parent.State == types.SessionActive {
		m.addMemberLocked(parent, ev.HostPID)
	}
	m.mu.Unlock()
	return nil, false
}

// createSession builds and registers a new AgentSession for a detected agent.
func (m *Manager) createSession(ev *types.SyscallEvent, kind types.AgentKind, exePath string) (*types.AgentSession, bool) {
	m.mu.Lock()
	// Idempotency: if this root pid, or this managed cgroup, is already an active
	// session, fold rather than duplicate (the OnExec descendant fold catches this
	// first; this is a defensive backstop on the same invariant).
	if s, ok := m.byRootPID[ev.HostPID]; ok && s.State == types.SessionActive {
		m.mu.Unlock()
		return s, false
	}
	if s, ok := m.byCgroup[ev.CgroupID]; ok && s.State == types.SessionActive &&
		s.CgroupPath != "" && ev.CgroupID == s.CgroupID {
		m.addMemberLocked(s, ev.HostPID)
		m.mu.Unlock()
		return s, false
	}

	id := newUUIDv7()
	sess := &types.AgentSession{
		ID:        id,
		Agent:     kind,
		RootPID:   ev.HostPID,
		CgroupID:  ev.CgroupID,
		StartTime: nowFrom(ev),
		State:     types.SessionActive,
		Coverage:  types.CoverageNone,
		Members:   []int32{ev.HostPID},
	}
	m.mu.Unlock()

	// cgroup placement, outside the lock (filesystem I/O). Moving the agent's
	// root process into an owned cgroup v2 subtree yields a stable kernel
	// attribution key (descendants inherit it) without touching the agent's
	// binary, config, hooks, or plugins. Gated by ManageCgroup: moving live
	// processes is invasive, so the default keeps them in place and uses the
	// existing cgroup id as the key.
	var (
		path    string
		cgid    uint64
		err     error
		managed bool
	)
	if m.ManageCgroup {
		path, cgid, err = m.placeInCgroup(ev.HostPID, id)
		managed = err == nil
		if err != nil {
			m.log.Warn("cgroup placement failed; falling back to event cgroup id",
				zap.String("session", id), zap.Int32("pid", ev.HostPID), zap.Error(err))
		}
	}

	m.mu.Lock()
	if managed {
		sess.CgroupPath = path
		sess.CgroupID = cgid
	}
	// Index by both the managed cgroup id (if any) and the original event cgroup
	// id, so lookups succeed whether or not placement took effect immediately.
	m.byID[id] = sess
	m.byRootPID[ev.HostPID] = sess
	m.pidIndex[ev.HostPID] = sess
	m.byCgroup[sess.CgroupID] = sess
	if ev.CgroupID != 0 && ev.CgroupID != sess.CgroupID {
		m.byCgroup[ev.CgroupID] = sess
	}
	m.mu.Unlock()

	m.log.Info("agent session detected",
		zap.String("session", id),
		zap.String("agent", string(kind)),
		zap.Int32("root_pid", ev.HostPID),
		zap.String("exe", exePath),
		zap.Uint64("cgroup_id", sess.CgroupID),
		zap.String("cgroup_path", sess.CgroupPath),
		zap.Bool("managed_cgroup", managed))

	if m.OnNewSession != nil {
		m.OnNewSession(sess)
	}
	return sess, true
}

// placeInCgroup creates a cgroup v2 directory at
// /sys/fs/cgroup/<cgroupParent>/session-<id>/ , moves pid into it by writing to
// cgroup.procs, and returns the cgroup path and its numeric id.
//
// The numeric cgroup id is the cgroupfs directory inode (Stat_t.Ino). This
// matches what the kernel's bpf_get_current_cgroup_id() helper returns, so the
// value lines up with the CgroupID carried on BPF-sourced SyscallEvents and can
// be used directly as the attribution key.
//
// Best-effort: any failure (missing cgroup2 mount, no write permission, missing
// parent slice) is returned to the caller, which falls back to the event's
// CgroupID as the key.
func (m *Manager) placeInCgroup(pid int32, sessionID string) (string, uint64, error) {
	dir := filepath.Join(cgroupRoot, m.cgroupParent, "session-"+sessionID)

	// 0750: the managed subtree; agents run unprivileged and need no access.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", 0, fmt.Errorf("mkdir cgroup %s: %w", dir, err)
	}

	// Move the process in. In cgroup v2 writing a pid to cgroup.procs migrates
	// the whole thread group; descendants then inherit this cgroup on fork.
	procsPath := filepath.Join(dir, "cgroup.procs")
	if err := os.WriteFile(procsPath, []byte(strconv.Itoa(int(pid))), 0o600); err != nil {
		return "", 0, fmt.Errorf("write %s: %w", procsPath, err)
	}

	cgid, err := cgroupInode(dir)
	if err != nil {
		return dir, 0, fmt.Errorf("stat cgroup %s: %w", dir, err)
	}
	return dir, cgid, nil
}

// firstLiveProcExcept returns the first pid listed in the cgroup's cgroup.procs
// other than exclude, or 0 if the cgroup holds no other live process. cgroup.procs
// lists only currently-live thread-group leaders in the cgroup, so a returned pid
// is live at read time. Called only on root exit, so the procfs read is not hot.
func firstLiveProcExcept(cgroupDir string, exclude int32) int32 {
	data, err := os.ReadFile(filepath.Join(cgroupDir, "cgroup.procs"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := strconv.Atoi(line)
		if err != nil || int32(p) == exclude {
			continue
		}
		if procAlive(int32(p)) { // cgroup.procs can briefly list an exiting pid
			return int32(p)
		}
	}
	return 0
}

// procAlive reports whether pid is a live, non-zombie process. cgroup.procs may
// momentarily still list a thread-group leader whose exit is already in flight;
// adopting such a pid as the new root would strand the session on a dead process,
// so a zombie/absent pid is rejected.
func procAlive(pid int32) bool {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "stat"))
	if err != nil {
		return false
	}
	// stat is "pid (comm) state ...": the state char follows the last ')'.
	if i := strings.LastIndexByte(string(data), ')'); i >= 0 && i+2 < len(data) {
		switch data[i+2] {
		case 'Z', 'X', 'x': // zombie / dead
			return false
		}
		return true
	}
	return false
}

// cgroupInode returns the inode number of a cgroupfs directory, which the kernel
// uses as the cgroup id (see bpf_get_current_cgroup_id).
func cgroupInode(dir string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Ino), nil
}

// addMemberLocked records pid as a member of sess. Caller holds mu.
func (m *Manager) addMemberLocked(sess *types.AgentSession, pid int32) {
	if _, ok := m.pidIndex[pid]; ok {
		return
	}
	sess.Members = append(sess.Members, pid)
	m.pidIndex[pid] = sess
}

// OnExit updates membership/lifecycle. Exit of the root pid ends the session
// (EndTime/State=ended) but keeps it in a bounded recent-history list.
func (m *Manager) OnExit(ev *types.SyscallEvent) {
	if ev == nil {
		return
	}
	m.mu.Lock()

	pid := ev.HostPID
	sess := m.pidIndex[pid]
	if sess == nil {
		m.mu.Unlock()
		return
	}

	var ended, exitedMember *types.AgentSession
	if sess.RootPID == pid {
		// A launcher root may re-exec into a child that becomes the real worker
		// (e.g. `node <cli>` spawning `node --max-old-space-size <cli>`, which owns
		// the TLS connections). If the root exits while the managed cgroup still
		// holds live processes, adopt a surviving pid as the new root and keep the
		// session (and its attach/enforcement) alive instead of ending it, which
		// would unregister the cgroup from the BPF capture map and drop the
		// surviving worker's traffic.
		if sess.CgroupPath != "" {
			if adopt := firstLiveProcExcept(sess.CgroupPath, pid); adopt != 0 {
				delete(m.pidIndex, pid)
				for i, mp := range sess.Members {
					if mp == pid {
						sess.Members = append(sess.Members[:i], sess.Members[i+1:]...)
						break
					}
				}
				delete(m.byRootPID, sess.RootPID)
				sess.RootPID = adopt
				m.byRootPID[adopt] = sess
				m.addMemberLocked(sess, adopt)
				m.mu.Unlock()
				m.log.Debug("session root re-pointed to surviving worker",
					zap.String("session", sess.ID), zap.Int32("old_root", pid), zap.Int32("new_root", adopt))
				return
			}
		}
		sess.State = types.SessionEnded
		sess.EndTime = nowFrom(ev)
		// Drop live indexes but keep byID reachable for late lookups; move to
		// history and evict the oldest if over capacity.
		for _, mp := range sess.Members {
			delete(m.pidIndex, mp)
		}
		delete(m.byRootPID, sess.RootPID)
		delete(m.byCgroup, sess.CgroupID)
		m.history = append(m.history, sess)
		if len(m.history) > m.historyMax {
			old := m.history[0]
			m.history = m.history[1:]
			delete(m.byID, old.ID)
		}
		m.log.Info("agent session ended",
			zap.String("session", sess.ID), zap.Int32("root_pid", pid))
		ended = sess
	} else {
		// Non-root member exit: remove from membership index.
		delete(m.pidIndex, pid)
		for i, mp := range sess.Members {
			if mp == pid {
				sess.Members = append(sess.Members[:i], sess.Members[i+1:]...)
				break
			}
		}
		exitedMember = sess
	}
	m.mu.Unlock()

	if ended != nil && m.OnSessionEnded != nil {
		m.OnSessionEnded(ended)
	}
	if exitedMember != nil && m.OnMemberExit != nil {
		m.OnMemberExit(exitedMember, pid)
	}
}

// LookupByCgroup returns the owning session for a cgroup id, if any.
func (m *Manager) LookupByCgroup(cgroupID uint64) (*types.AgentSession, bool) {
	if cgroupID == 0 {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.byCgroup[cgroupID]
	return s, ok
}

// LookupByPID returns the owning session for any member host pid, if any. It is
// the attribution fallback for semantic events when the cgroup id is unavailable
// (e.g. cgroup could not be read, so byCgroup misses).
func (m *Manager) LookupByPID(pid int32) (*types.AgentSession, bool) {
	if pid <= 0 {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.pidIndex[pid]
	return s, ok
}

// Enrich attaches session and host/meta references to a system event in place.
// Nil-safe on both the event and on a missing session.
func (m *Manager) Enrich(ev *types.SyscallEvent) {
	if ev == nil {
		return
	}

	// Pid-tree membership is the precise key (scopes within a shared cgroup);
	// fall back to the cgroup index for descendants not individually tracked yet.
	m.mu.RLock()
	sess := m.pidIndex[ev.HostPID]
	if sess == nil {
		sess = m.byCgroup[ev.CgroupID]
	}
	m.mu.RUnlock()

	if sess != nil {
		ev.Session = &types.SessionRef{SessionID: sess.ID, Agent: sess.Agent}
	}

	// Host identity: NodeName is the host's hostname.
	if ev.Meta == nil {
		ev.Meta = &types.AgentMeta{}
	}
	if ev.Meta.NodeName == "" {
		ev.Meta.NodeName = m.nodeName
	}
}

// List returns a snapshot of all currently tracked sessions (active + history).
func (m *Manager) List() []*types.AgentSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*types.AgentSession, 0, len(m.byID))
	for _, s := range m.byID {
		out = append(out, s)
	}
	return out
}

// CgroupHasActiveSession reports whether any active session (other than excludeID)
// still occupies the given cgroup id. Used at session teardown so ending one
// session does not rip cgroup-level enforcement (ak_sessions / posture) out from
// under another live session sharing the same cgroup, e.g. a child process that
// was mis-onboarded as its own session on the agent's managed cgroup.
func (m *Manager) CgroupHasActiveSession(cgid uint64, excludeID string) bool {
	if cgid == 0 {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.byID {
		if s.ID != excludeID && s.State == types.SessionActive && s.CgroupID == cgid {
			return true
		}
	}
	return false
}

// SetAttachPlan records the resolver's plan and its coverage on a session.
func (m *Manager) SetAttachPlan(sessionID string, plan *types.AttachPlan) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.byID[sessionID]; ok {
		s.AttachPlan = plan
		if plan != nil {
			s.Coverage = plan.Coverage
		}
	}
}

// SetCoverage records the recovered semantic coverage on a session.
func (m *Manager) SetCoverage(sessionID string, c types.SemanticCoverage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.byID[sessionID]; ok {
		s.Coverage = c
	}
}

// LookupByID returns the live session struct for an id.
func (m *Manager) LookupByID(sessionID string) (*types.AgentSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.byID[sessionID]
	return s, ok
}

// NoteWireIntent records that a semantic event was recovered from the live
// plaintext boundary for this session.
func (m *Manager) NoteWireIntent(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.byID[sessionID]; ok {
		s.WireIntents++
	}
}

// WireIntents reports how many semantic events came off the live boundary.
func (m *Manager) WireIntents(sessionID string) (int64, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.byID[sessionID]
	if !ok {
		return 0, false
	}
	return s.WireIntents, true
}

// MarkTampered flags a session whose binary build-id did not match known-good.
func (m *Manager) MarkTampered(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.byID[sessionID]; ok {
		s.Tampered = true
	}
}

// nowFrom prefers the event's wall-clock time, falling back to time.Now().
func nowFrom(ev *types.SyscallEvent) time.Time {
	if ev != nil && !ev.Time.IsZero() {
		return ev.Time
	}
	return time.Now()
}

// newUUIDv7 returns a UUIDv7 string, falling back to a v4 if the monotonic
// generator errors (never expected on Linux).
func newUUIDv7() string {
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	return uuid.NewString()
}

// cgroupNamePrefix marks a cgroup directory as one AgentKnox created. Removal is
// gated on it so a session that never got its own cgroup -- and therefore carries
// the path of a cgroup belonging to somebody else -- can never delete it.
const cgroupNamePrefix = "session-"

const (
	// cgroupReleaseRetries/Wait bound how long teardown waits for a straggler to
	// leave. cgroupfs refuses rmdir with EBUSY while any process remains, and a
	// process that has just been signalled takes a moment to be reaped.
	cgroupReleaseRetries = 5
	cgroupReleaseWait    = 200 * time.Millisecond
)

// releaseCgroup removes a managed cgroup directory, retrying while the kernel
// still reports it busy.
//
// rmdir, not RemoveAll: cgroupfs removes an empty cgroup even though it lists
// dozens of interface files, and the kernel refuses while any process or child
// cgroup remains -- so this cannot take live processes with it. A recursive
// delete on a path that turned out not to be a cgroup would be catastrophic.
func releaseCgroup(dir string, retries int, wait time.Duration) error {
	if dir == "" || !strings.Contains(dir, cgroupNamePrefix) {
		return nil
	}
	var err error
	for i := 0; ; i++ {
		if err = os.Remove(dir); err == nil || os.IsNotExist(err) {
			return nil
		}
		if i >= retries {
			return err
		}
		time.Sleep(wait)
	}
}

// ReleaseSessionCgroup removes the cgroup directory created for a session that
// has ended. Without it every session AgentKnox ever managed leaves a cgroup
// behind: the directory outlives the daemon, and each one keeps kernel-side
// cgroup state alive.
func (m *Manager) ReleaseSessionCgroup(s *types.AgentSession) {
	if s == nil || s.CgroupPath == "" {
		return
	}
	if err := releaseCgroup(s.CgroupPath, cgroupReleaseRetries, cgroupReleaseWait); err != nil {
		// Not silent: what is left here is reclaimed only by the next startup
		// sweep, and a persistent EBUSY means processes outlived the session.
		m.log.Warn("could not release the session cgroup; leaving it for the next startup sweep",
			zap.String("session", s.ID), zap.String("cgroup", s.CgroupPath), zap.Error(err))
	}
}

// SweepOrphanCgroups reclaims managed cgroups left behind by a previous daemon
// run -- a crash, a kill -9, or a release that hit EBUSY. Only empty ones are
// removed, so a cgroup still holding processes (possibly another daemon's live
// session) is left alone. Returns how many were reclaimed.
func (m *Manager) SweepOrphanCgroups() int {
	removed := 0
	for _, dir := range orphanCgroupDirs(filepath.Join(cgroupRoot, m.cgroupParent)) {
		if err := os.Remove(dir); err == nil {
			removed++
		}
	}
	if removed > 0 {
		m.log.Info("reclaimed orphaned agent cgroups", zap.Int("count", removed))
	}
	return removed
}

// orphanCgroupDirs lists the managed cgroups under parent that hold no
// processes. A cgroup that still lists a pid belongs to a live session --
// possibly another daemon's -- and a directory we did not create is never a
// candidate, whatever it contains.
func orphanCgroupDirs(parent string) []string {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil // no managed parent slice yet: nothing to reclaim
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), cgroupNamePrefix) {
			continue
		}
		dir := filepath.Join(parent, e.Name())
		b, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
		if err != nil || len(strings.TrimSpace(string(b))) != 0 {
			continue // unreadable, or still holding processes
		}
		out = append(out, dir)
	}
	return out
}
