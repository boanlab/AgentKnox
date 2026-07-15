// SPDX-License-Identifier: Apache-2.0
// Package enforce implements the Enforcer. It installs
// pre-enforcement rules into the BPF-LSM shared maps (loaded by internal/sensor)
// and applies runtime decisions (Block via the kernel file map, Kill via signal).
//
// Backends:
//   - BPFEnforcer  ("bpf-lsm"): the primary path. Pre-op file_open denial is
//     driven by the ak_enforce_file map (fnv1a(path) -> action) combined with the
//     ak_sessions enforce flag; process termination is done with SIGKILL.
//   - UserspaceEnforcer ("userspace"): the fallback for kernels without BPF-LSM.
//     It enforces post-hoc by terminating policy-violating processes (see
//     userspace.go); out-of-band AppArmor confinement of running processes is
//     not feasible, so this is the honest fallback.
package enforce

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"github.com/boanlab/agentknox/internal/bpf2frame"
	"github.com/boanlab/agentknox/internal/pipeline"
	"github.com/boanlab/agentknox/pkg/types"
)

// Session flag bits, byte-locked to bpf/maps.bpf.h (AK_SESS_MONITOR / ENFORCE).
const (
	sessMonitor    uint32 = 0x1
	sessEnforce    uint32 = 0x2
	sessDenyCode   uint32 = 0x4
	sessDenyEgress uint32 = 0x8
)

// Forbidden-operation bitmask, byte-locked to bpf/wire.bpf.h (AK_OP_*). Stored as
// the value in ak_enforce_file so distinct operations on the same path can be
// forbidden independently.
const (
	opOpen   uint32 = 0x1
	opExec   uint32 = 0x2
	opDelete uint32 = 0x4
	opRename uint32 = 0x8
	opChmod  uint32 = 0x10
	opChown  uint32 = 0x20
	opWrite  uint32 = 0x40 // write-open specifically (read-opens still allowed)
)

// selfProtectOps is the op set applied to AgentKnox's own paths: an enforce-mode
// session member may not write, delete, rename, or change ownership/mode of them.
const selfProtectOps = opWrite | opDelete | opRename | opChmod | opChown

// netBlock is the ak_enforce_net value (any nonzero = block).
const netBlock uint32 = 1

// opBit maps a policy operation to its forbidden-op bit.
func opBit(operation string) uint32 {
	switch operation {
	case "exec":
		return opExec
	case "delete":
		return opDelete
	case "rename":
		return opRename
	case "chmod":
		return opChmod
	case "chown":
		return opChown
	default: // open|read|write
		return opOpen
	}
}

// BPFEnforcer is the BPF-LSM backend. It writes to two maps shared with the
// System Sensor: ak_sessions (cgroup_id -> flags) and ak_enforce_file
// (fnv1a-64(path) -> action). The LSM program denies file_open when the current
// cgroup carries the enforce flag AND fnv1a(fullpath) resolves to actBlock.
type BPFEnforcer struct {
	sessionMap        *ebpf.Map
	sessionPidsMap    *ebpf.Map
	enforceFileMap    *ebpf.Map
	enforceDirMap     *ebpf.Map
	enforceNetMap     *ebpf.Map
	enforceNet6Map    *ebpf.Map
	postureMap        *ebpf.Map
	taintFilesMap     *ebpf.Map
	sensitiveFilesMap *ebpf.Map
	flagsMap          *ebpf.Map
	dbDenyTablesMap   *ebpf.Map
	agentSigsMap      *ebpf.Map
	dryRun            bool
	denyCode          bool // policy wants agent-written-code execution blocked
	log               *zap.Logger

	mu        sync.Mutex
	installed map[uint64]struct{} // file hashes written into ak_enforce_file (cleanup)
	instDir   map[uint64]struct{} // dir hashes written into ak_enforce_dir
	instTaint map[uint64]struct{} // path hashes written into ak_taint_files
	instSelf  map[uint64]struct{} // self-protection hashes (survive ClearRules)
}

// Maps bundles the shared BPF maps the enforcer writes to.
type Maps struct {
	Sessions       *ebpf.Map
	SessionPids    *ebpf.Map
	EnforceFile    *ebpf.Map
	EnforceDir     *ebpf.Map
	EnforceNet     *ebpf.Map
	EnforceNet6    *ebpf.Map
	Posture        *ebpf.Map
	TaintFiles     *ebpf.Map
	SensitiveFiles *ebpf.Map
	Flags          *ebpf.Map
	DBDenyTables   *ebpf.Map
	AgentSigs      *ebpf.Map
}

// posture bits, byte-locked to bpf/maps.bpf.h (AK_POSTURE_*).
const (
	postureDenyEgress      uint32 = 0x1
	postureDenyTaintedCode uint32 = 0x2
)

// taint bits mirror AK_TAINT_* in bpf/maps.bpf.h.
const (
	taintWritten uint32 = 0x1 // agent wrote the file (content-agnostic provenance)
	taintCode    uint32 = 0x2 // detected as code (shebang / exec-bit / extension)
	taintPersist uint32 = 0x4 // agent-registered persistence artifact (cron/systemd/hook)
)

// global control flags, byte-locked to bpf/maps.bpf.h (AK_FLAG_*).
const (
	flagPersistArmed uint32 = 0x1
	flagDBBlockArmed uint32 = 0x8 // >=1 denied DB table installed (pre-op query block)
)

// dbDenyTableSlots mirrors the ak_db_deny_tables array capacity in bpf/maps.bpf.h.
const dbDenyTableSlots = 4

// dbPat mirrors struct ak_db_pat in bpf/maps.bpf.h.
type dbPat struct {
	Len uint32
	Pat [32]byte
}

// compile-time interface checks.
var (
	_ pipeline.Enforcer = (*BPFEnforcer)(nil)
)

// New constructs a BPFEnforcer over the shared BPF maps.
func New(m Maps, dryRun bool, log *zap.Logger) *BPFEnforcer {
	if log == nil {
		log = zap.NewNop()
	}
	return &BPFEnforcer{
		sessionMap:        m.Sessions,
		sessionPidsMap:    m.SessionPids,
		enforceFileMap:    m.EnforceFile,
		enforceDirMap:     m.EnforceDir,
		enforceNetMap:     m.EnforceNet,
		enforceNet6Map:    m.EnforceNet6,
		postureMap:        m.Posture,
		taintFilesMap:     m.TaintFiles,
		sensitiveFilesMap: m.SensitiveFiles,
		flagsMap:          m.Flags,
		dbDenyTablesMap:   m.DBDenyTables,
		agentSigsMap:      m.AgentSigs,
		dryRun:            dryRun,
		log:               log,
		installed:         make(map[uint64]struct{}),
		instDir:           make(map[uint64]struct{}),
		instTaint:         make(map[uint64]struct{}),
		instSelf:          make(map[uint64]struct{}),
	}
}

// PopulateAgentSigs seeds the ak_agent_sigs map with fnv1a(signature) -> flags so
// the bprm hook can recognize an agent binary at exec time and arm its session
// in-kernel, ahead of the userspace exec-event round-trip. Flags are MONITOR
// (dry-run) or MONITOR|ENFORCE, matching EnforceSession.
func (e *BPFEnforcer) PopulateAgentSigs(signatures []string) {
	if e.agentSigsMap == nil {
		return
	}
	flags := sessMonitor
	if !e.dryRun {
		flags |= sessEnforce
		if e.denyCode {
			flags |= sessDenyCode
		}
	}
	for _, s := range signatures {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		h := bpf2frame.HashString(s) // byte-identical to ak_fnv1a_basename on the basename
		if err := e.agentSigsMap.Put(h, flags); err != nil {
			e.log.Warn("enforce: seed agent signature", zap.String("sig", s), zap.Error(err))
		}
	}
	e.log.Info("enforce: agent signatures seeded for in-kernel exec-time arming",
		zap.Strings("signatures", signatures), zap.Uint32("flags", flags))
}

// RegisterAgentBinary seeds ONE resolved binary basename into ak_agent_sigs at
// runtime, so the kernel arms a worker the agent re-execs under that name. Needed
// when the agent is reached through a symlink whose target basename is not a
// configured signature: the bprm hook sees the resolved filename, which may not
// match a generic signature such as `claude`. The caller must filter generic
// interpreter names so unrelated node/python/bash processes are never armed.
func (e *BPFEnforcer) RegisterAgentBinary(name string) {
	if e.agentSigsMap == nil || name == "" {
		return
	}
	flags := sessMonitor
	if !e.dryRun {
		flags |= sessEnforce
		if e.denyCode {
			flags |= sessDenyCode
		}
	}
	h := bpf2frame.HashString(strings.ToLower(name))
	if err := e.agentSigsMap.Put(h, flags); err != nil {
		e.log.Warn("enforce: register agent binary", zap.String("name", name), zap.Error(err))
		return
	}
	e.log.Info("enforce: registered agent worker binary for in-kernel arming",
		zap.String("name", name), zap.Uint32("flags", flags))
}

// InstallSelfProtection forbids an enforce-mode session member from writing,
// deleting, renaming, or changing ownership/mode of AgentKnox's own paths (the
// daemon binary, config file, policy directory, WAL, and archive). Prevents a
// co-privileged agent from disabling its own policy (the policy dir is
// hot-reloaded) or tampering with the audit trail. AgentKnox itself is
// self-excluded (ak_session_flags returns 0 for its own tgid). Entries are
// tracked separately from user rules so a policy hot-reload (ClearRules) never
// drops self-protection.
func (e *BPFEnforcer) InstallSelfProtection(files, dirs []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, f := range files {
		if !isExactPath(f) {
			continue
		}
		h := bpf2frame.HashString(f)
		if err := e.addSelfFileOp(h); err != nil {
			e.log.Warn("enforce: self-protect file", zap.String("path", f), zap.Error(err))
		}
	}
	for _, d := range dirs {
		d = strings.TrimRight(d, "/")
		if d == "" || !strings.HasPrefix(d, "/") {
			continue
		}
		h := bpf2frame.HashString(d)
		// ak_enforce_dir protects everything UNDER the tree; ak_enforce_file on the
		// same hash protects the directory node itself (delete/rename of the dir).
		if e.enforceDirMap != nil {
			var cur uint32
			_ = e.enforceDirMap.Lookup(h, &cur)
			if err := e.enforceDirMap.Put(h, cur|selfProtectOps); err != nil {
				e.log.Warn("enforce: self-protect dir", zap.String("dir", d), zap.Error(err))
				continue
			}
		}
		if err := e.addSelfFileOp(h); err != nil {
			e.log.Warn("enforce: self-protect dir node", zap.String("dir", d), zap.Error(err))
		}
	}
	e.log.Info("enforce: self-protection installed",
		zap.Int("files", len(files)), zap.Int("dirs", len(dirs)), zap.Bool("dry_run", e.dryRun))
}

// addSelfFileOp writes selfProtectOps into ak_enforce_file and records the hash
// in instSelf (not installed), so ClearRules leaves it intact. Caller holds mu.
func (e *BPFEnforcer) addSelfFileOp(h uint64) error {
	if e.enforceFileMap == nil {
		return fmt.Errorf("enforce-file map is nil")
	}
	var cur uint32
	_ = e.enforceFileMap.Lookup(h, &cur)
	if err := e.enforceFileMap.Put(h, cur|selfProtectOps); err != nil {
		return err
	}
	e.instSelf[h] = struct{}{}
	return nil
}

// Backend identifies this enforcer.
func (e *BPFEnforcer) Backend() string { return "bpf-lsm" }

// InstallRules pre-installs kernel enforcement for Block rules that target an
// exact file path. Directory-prefix and wildcard rules cannot be pre-enforced by
// the exact-hash BPF map; those are logged and left to post-hoc handling by the
// policy engine / Apply.
//
// dryRun still installs the map entries — they only take effect for a cgroup that
// also carries the enforce flag, and in dryRun EnforceSession never sets it, so
// nothing is actually blocked.
//
// A rule the kernel refuses (a full map, a malformed CIDR) does not abandon the
// rules after it: every rule is attempted, so which rules are enforced never
// depends on their order in the policy file. What could not be installed is
// counted per map and named in the returned error, since a partially installed
// rule set is a narrower enforcement envelope than the operator asked for.
func (e *BPFEnforcer) InstallRules(rules []pipeline.KernelRule) error {
	if e.enforceFileMap == nil {
		return fmt.Errorf("enforce: enforce-file map is nil")
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	var installed, skipped int
	// dropped counts rules the kernel refused, keyed by the map that refused them,
	// with the first error per map kept for the report.
	dropped := map[string]int{}
	firstErr := map[string]error{}
	drop := func(m string, r pipeline.KernelRule, err error) {
		dropped[m]++
		if _, ok := firstErr[m]; !ok {
			firstErr[m] = err
		}
		e.log.Error("enforce: kernel rule NOT installed; this rule is not enforced",
			zap.String("policy", r.PolicyName), zap.String("map", m),
			zap.String("category", string(r.Category)), zap.String("op", r.Operation),
			zap.Error(err))
	}
	dbSlot := 0
	for _, r := range rules {
		if r.Effect != types.EffectBlock {
			continue
		}
		if r.Category == types.CategoryDatabase {
			if err := e.installDBRule(r, &dbSlot); err != nil {
				drop("ak_db_deny_tables", r, err)
			} else {
				installed++
			}
			continue
		}
		if r.Category == types.CategoryNetwork {
			if err := e.installNetRule(r); err != nil {
				drop("ak_enforce_net", r, err)
			} else {
				installed++
			}
			continue
		}
		// Path-based pre-block: file operations (open/read/write, delete) and
		// exec (process category). Op distinguishes which LSM hook enforces.
		if r.Category != types.CategoryFile && !(r.Category == types.CategoryProcess && r.Operation == "exec") {
			e.log.Debug("enforce: skip non-path kernel rule",
				zap.String("policy", r.PolicyName),
				zap.String("category", string(r.Category)))
			skipped++
			continue
		}
		path := r.PathPrefix
		op := opBit(r.Operation)
		if strings.HasSuffix(path, "/") && len(path) > 1 {
			// Directory rule: every file under this tree is forbidden. Hash the
			// dir without the trailing slash (the ancestor form the LSM checks).
			dir := strings.TrimRight(path, "/")
			if err := e.addDirOp(bpf2frame.HashString(dir), op); err != nil {
				drop("ak_enforce_dir", r, fmt.Errorf("install dir %q: %w", dir, err))
				continue
			}
			installed++
			e.log.Info("enforce: installed directory forbid rule",
				zap.String("policy", r.PolicyName), zap.String("dir", dir),
				zap.String("op", r.Operation), zap.Bool("dry_run", e.dryRun))
			continue
		}
		if !isExactPath(path) {
			e.log.Info("enforce: rule path is neither an absolute file nor a directory prefix; deferring to post-hoc policy",
				zap.String("policy", r.PolicyName), zap.String("path", path))
			skipped++
			continue
		}
		if err := e.addFileOp(bpf2frame.HashString(path), op); err != nil {
			drop("ak_enforce_file", r, fmt.Errorf("install %q: %w", path, err))
			continue
		}
		installed++
		e.log.Info("enforce: installed exact-path forbid rule",
			zap.String("policy", r.PolicyName),
			zap.String("path", path),
			zap.String("op", r.Operation),
			zap.Bool("dry_run", e.dryRun))
	}
	if len(dropped) > 0 {
		total := 0
		maps := make([]string, 0, len(dropped))
		for m, n := range dropped {
			total += n
			maps = append(maps, m)
		}
		sort.Strings(maps)
		parts := make([]string, 0, len(maps))
		for _, m := range maps {
			parts = append(parts, fmt.Sprintf("%s: %d dropped (first: %v)", m, dropped[m], firstErr[m]))
		}
		e.log.Error("enforce: kernel rule set is INCOMPLETE; the dropped rules are not enforced in the kernel",
			zap.Int("installed", installed), zap.Int("dropped", total),
			zap.Int("skipped", skipped), zap.Strings("maps", maps),
			zap.Bool("dry_run", e.dryRun))
		return fmt.Errorf("enforce: %d of %d block rules could not be installed (%s)",
			total, total+installed, strings.Join(parts, "; "))
	}
	e.log.Info("enforce: InstallRules complete",
		zap.Int("installed", installed),
		zap.Int("skipped", skipped),
		zap.Bool("dry_run", e.dryRun))
	return nil
}

// ClearRules removes installed file/dir/network rules for hot-reload; session
// flags, posture, and provenance taint are preserved (they track live state, not
// policy).
func (e *BPFEnforcer) ClearRules() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.enforceFileMap != nil {
		for h := range e.installed {
			_ = e.enforceFileMap.Delete(h)
		}
	}
	if e.enforceDirMap != nil {
		for h := range e.instDir {
			_ = e.enforceDirMap.Delete(h)
		}
	}
	if e.enforceNetMap != nil {
		var key lpmKey
		var val uint32
		it := e.enforceNetMap.Iterate()
		var keys []lpmKey
		for it.Next(&key, &val) {
			keys = append(keys, key)
		}
		for _, k := range keys {
			_ = e.enforceNetMap.Delete(k)
		}
	}
	if e.enforceNet6Map != nil {
		var key lpmKey6
		var val uint32
		it := e.enforceNet6Map.Iterate()
		var keys []lpmKey6
		for it.Next(&key, &val) {
			keys = append(keys, key)
		}
		for _, k := range keys {
			_ = e.enforceNet6Map.Delete(k)
		}
	}
	if e.dbDenyTablesMap != nil {
		var empty dbPat
		for i := 0; i < dbDenyTableSlots; i++ {
			_ = e.dbDenyTablesMap.Put(uint32(i), empty)
		}
	}
	e.installed = make(map[uint64]struct{})
	e.instDir = make(map[uint64]struct{})
	return nil
}

// addFileOp ORs a forbidden-op bit into the ak_enforce_file entry for a path
// hash, so multiple rules on the same path accumulate.
func (e *BPFEnforcer) addFileOp(h uint64, op uint32) error {
	if e.enforceFileMap == nil {
		return fmt.Errorf("enforce-file map is nil")
	}
	var cur uint32
	_ = e.enforceFileMap.Lookup(h, &cur) // absent -> cur stays 0
	if err := e.enforceFileMap.Put(h, cur|op); err != nil {
		return err
	}
	e.installed[h] = struct{}{}
	return nil
}

// addDirOp ORs a forbidden-op bit into the ak_enforce_dir entry for a directory
// path hash (matched against every ancestor of a target path by the LSM hooks).
func (e *BPFEnforcer) addDirOp(h uint64, op uint32) error {
	if e.enforceDirMap == nil {
		return fmt.Errorf("enforce-dir map is nil")
	}
	var cur uint32
	_ = e.enforceDirMap.Lookup(h, &cur)
	if err := e.enforceDirMap.Put(h, cur|op); err != nil {
		return err
	}
	e.instDir[h] = struct{}{}
	return nil
}

// EnforceSession maps a session's cgroup into the enforcement domain. It sets the
// monitor flag always, and the enforce flag unless dryRun. Idempotent.
func (e *BPFEnforcer) EnforceSession(sess *types.AgentSession) error {
	if sess == nil {
		return fmt.Errorf("enforce: nil session")
	}
	if e.sessionMap == nil {
		return fmt.Errorf("enforce: session map is nil")
	}
	flags := sessMonitor
	if !e.dryRun {
		flags |= sessEnforce
		if e.denyCode {
			flags |= sessDenyCode
		}
	}
	// Dedicated-cgroup key (manageCgroup=true) — coarse.
	if sess.CgroupID != 0 {
		if err := e.armKey(e.sessionMap, sess.CgroupID, flags); err != nil {
			return fmt.Errorf("enforce: set session flags for cgroup %d: %w", sess.CgroupID, err)
		}
	}
	// Pid-scoped keys — precise, used with shared cgroups (manageCgroup=false).
	if e.sessionPidsMap != nil {
		for _, pid := range e.sessionPids(sess) {
			if err := e.armKey(e.sessionPidsMap, uint32(pid), flags); err != nil {
				e.log.Warn("enforce: arm session pid", zap.Int32("pid", pid), zap.Error(err))
			}
		}
	}
	e.log.Info("enforce: session mapped into enforcement domain",
		zap.String("session", sess.ID),
		zap.Uint64("cgroup", sess.CgroupID),
		zap.Int("pids", len(e.sessionPids(sess))),
		zap.Uint32("flags", flags),
		zap.Bool("dry_run", e.dryRun))
	return nil
}

// armKey writes flags into a session map without dropping bits already in force.
// The union matters because the kernel writes to these same keys: a sensitive
// read arms deny-egress on the reading pid in ak_lsm_file_open, and a plain Put
// from the re-arm sweep would erase that arm a moment later. Deny-tainted-code is
// the exception, following the live policy so a hot-reload that drops the rule
// also drops the bit.
func (e *BPFEnforcer) armKey(m *ebpf.Map, key any, want uint32) error {
	if m == nil {
		return fmt.Errorf("session map is nil")
	}
	var cur uint32
	if err := m.Lookup(key, &cur); err == nil {
		next := cur | want
		if !e.denyCode {
			next &^= sessDenyCode
		}
		if next == cur {
			return nil
		}
		want = next
	}
	if err := m.Put(key, want); err != nil {
		if errors.Is(err, unix.E2BIG) {
			return fmt.Errorf("%w (session map full at %d entries; a new member cannot be armed)",
				err, m.MaxEntries())
		}
		return err
	}
	return nil
}

// EnforcePID upgrades a single member pid to the current enforce flags (called as
// the agent's process tree grows).
func (e *BPFEnforcer) EnforcePID(pid int32) {
	if e.sessionPidsMap == nil || pid <= 0 {
		return
	}
	flags := sessMonitor
	if !e.dryRun {
		flags |= sessEnforce
		if e.denyCode {
			flags |= sessDenyCode
		}
	}
	if err := e.armKey(e.sessionPidsMap, uint32(pid), flags); err != nil {
		e.log.Warn("enforce: arm member pid", zap.Int32("pid", pid), zap.Error(err))
	}
}

// SetPidEgressDeny ORs the deny-egress flag into an armed pid's session entry, so the
// socket_connect hook refuses its (and its fork children's) outbound connects. No-op
// in dryRun or if the pid is not an armed member.
func (e *BPFEnforcer) SetPidEgressDeny(pid int32) {
	if e.sessionPidsMap == nil || pid <= 0 || e.dryRun {
		return
	}
	var cur uint32
	if err := e.sessionPidsMap.Lookup(uint32(pid), &cur); err != nil {
		return
	}
	if cur&sessDenyEgress != 0 {
		return
	}
	if err := e.sessionPidsMap.Put(uint32(pid), cur|sessDenyEgress); err != nil {
		e.log.Warn("enforce: arm deny-egress on pid; egress stays permitted for it",
			zap.Int32("pid", pid), zap.Error(err))
	}
}

// setPostureBit ORs (enable) or ANDs-NOT (disable) a posture bit for a cgroup. It
// reports whether the requested posture is now in force, so a caller never
// announces a posture the map write did not accept.
func (e *BPFEnforcer) setPostureBit(cgroupID uint64, bit uint32, enable bool) bool {
	if e.postureMap == nil || cgroupID == 0 || e.dryRun {
		return false
	}
	var cur uint32
	_ = e.postureMap.Lookup(cgroupID, &cur)
	next := cur
	if enable {
		next |= bit
	} else {
		next &^= bit
	}
	if next == cur {
		return true
	}
	if next == 0 {
		_ = e.postureMap.Delete(cgroupID)
		return true
	}
	if err := e.postureMap.Put(cgroupID, next); err != nil {
		e.log.Warn("enforce: posture write rejected; the requested posture is NOT in force",
			zap.Uint64("cgroup", cgroupID), zap.Uint32("bit", bit),
			zap.Int("capacity", int(e.postureMap.MaxEntries())), zap.Error(err))
		return false
	}
	return true
}

// SetNetPosture sets/clears deny-all-egress for a session's cgroup — the
// pre-block escalation used when a session becomes tainted.
func (e *BPFEnforcer) SetNetPosture(cgroupID uint64, denyEgress bool) {
	if e.setPostureBit(cgroupID, postureDenyEgress, denyEgress) && denyEgress {
		e.log.Info("enforce: deny-egress posture set", zap.Uint64("cgroup", cgroupID))
	}
}

// SetDenyCode records whether the active policy wants agent-written-code execution
// blocked. When set, the deny-tainted-code bit is written into the SESSION flags at
// agent arming and session enforcement, so it fork-propagates to the whole agent
// process tree (robust to a multi-cgroup agent) and is present before the agent's
// first write. Call before PopulateAgentSigs and session enforcement.
func (e *BPFEnforcer) SetDenyCode(enable bool) { e.denyCode = enable }

// SetTaintedCodePosture enables/disables blocking of agent-written code
// execution (and interpreter reads) for a session's cgroup — provenance-taint
// execution control (IFC-style).
func (e *BPFEnforcer) SetTaintedCodePosture(cgroupID uint64, enable bool) {
	if e.setPostureBit(cgroupID, postureDenyTaintedCode, enable) && enable {
		e.log.Info("enforce: deny-tainted-code posture set", zap.Uint64("cgroup", cgroupID))
	}
}

// TaintFile marks an absolute path with provenance taint. Every agent write sets
// AK_TAINT_WRITTEN (content-agnostic — blocks DIRECT exec); code=true also sets
// AK_TAINT_CODE (shebang/exec-bit/extension — blocks interpreter READ). Bits
// accumulate (a file written then chmod'd +x gains the code bit). Robust to
// copies: a copy is itself an agent write and gets re-tainted by the caller.
func (e *BPFEnforcer) TaintFile(path string, code bool) {
	if e.taintFilesMap == nil || !isExactPath(path) {
		return
	}
	bits := taintWritten
	if code {
		bits |= taintCode
	}
	h := bpf2frame.HashString(path)
	e.mu.Lock()
	defer e.mu.Unlock()
	var cur uint32
	_ = e.taintFilesMap.Lookup(h, &cur)
	next := cur | bits
	if next == cur {
		return // nothing new
	}
	if err := e.taintFilesMap.Put(h, next); err != nil {
		e.log.Warn("enforce: taint file", zap.String("path", path), zap.Error(err))
		return
	}
	e.instTaint[h] = struct{}{}
	e.log.Info("enforce: tainted agent-written file",
		zap.String("path", path), zap.Bool("code", code))
}

// MarkSensitivePath records an absolute path as a sensitive SOURCE (a developer
// secret) in ak_sensitive_files, so a monitored agent's read-open of it arms
// deny-egress on the reading pid synchronously in-kernel (io_uring-immune, race-free).
// Keyed by the same HashString as TaintFile, so the in-kernel ak_fnv1a(d_path) matches.
func (e *BPFEnforcer) MarkSensitivePath(path string) {
	if e.sensitiveFilesMap == nil || e.dryRun || !isExactPath(path) {
		return
	}
	h := bpf2frame.HashString(path)
	one := uint32(1)
	if err := e.sensitiveFilesMap.Put(h, one); err != nil {
		e.log.Warn("enforce: mark sensitive", zap.String("path", path), zap.Error(err))
		return
	}
	e.log.Info("enforce: sensitive source marked (in-kernel read-taint egress arm)",
		zap.String("path", path))
}

// armFlag ORs a global control-flag bit into ak_flags[0].
func (e *BPFEnforcer) armFlag(bit uint32) {
	if e.flagsMap == nil {
		return
	}
	var key, cur uint32
	_ = e.flagsMap.Lookup(key, &cur)
	if next := cur | bit; next != cur {
		_ = e.flagsMap.Put(key, next)
	}
}

// TaintPersist marks an absolute path as an agent-registered persistence artifact
// (a cron job, systemd unit, or git hook the agent wrote), so the bprm hook
// attributes later execution of that artifact even to an out-of-tree process
// (cron/systemd) that reparented away from the session (observe only; blocking is
// a normal policy rule). Arms the global gate so the bprm hook only pays the
// extra d_path cost once such an artifact exists.
func (e *BPFEnforcer) TaintPersist(path string) {
	if e.taintFilesMap == nil || !isExactPath(path) {
		return
	}
	h := bpf2frame.HashString(path)
	e.mu.Lock()
	defer e.mu.Unlock()
	var cur uint32
	_ = e.taintFilesMap.Lookup(h, &cur)
	next := cur | taintPersist
	if next != cur {
		if err := e.taintFilesMap.Put(h, next); err != nil {
			e.log.Warn("enforce: taint persist", zap.String("path", path), zap.Error(err))
			return
		}
		e.instTaint[h] = struct{}{}
		e.log.Info("enforce: tainted persistence artifact", zap.String("path", path))
	}
	e.armFlag(flagPersistArmed)
}

// IsTaintedWritten reports whether an absolute path is marked agent-written in
// the kernel taint map. Used by the userspace interpreter-script check.
func (e *BPFEnforcer) IsTaintedWritten(path string) bool {
	if e.taintFilesMap == nil || !isExactPath(path) {
		return false
	}
	var v uint32
	if err := e.taintFilesMap.Lookup(bpf2frame.HashString(path), &v); err != nil {
		return false
	}
	return v&taintWritten != 0
}

func (e *BPFEnforcer) sessionPids(sess *types.AgentSession) []int32 {
	seen := map[int32]struct{}{}
	var out []int32
	add := func(p int32) {
		if p > 1 {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
	}
	add(sess.RootPID)
	for _, p := range sess.Members {
		add(p)
	}
	// Include every already-existing descendant of the root, discovered from /proc.
	// The Members list is built from exec events, so a pre-forked worker (e.g. a
	// node worker pool) may be absent and would escape enforcement, since the fork
	// tracepoint only propagates tags forward from an already-tagged parent.
	for _, p := range descendantsOf(sess.RootPID) {
		add(p)
	}
	return out
}

// descendantsOf returns every live descendant pid of root by walking /proc once and
// following PPid links. Best-effort: unreadable/vanished entries are skipped.
func descendantsOf(root int32) []int32 {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	children := map[int32][]int32{}
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		pid64, err := strconv.Atoi(de.Name())
		if err != nil {
			continue
		}
		pid := int32(pid64)
		ppid := ppidOf(pid)
		if ppid > 0 {
			children[ppid] = append(children[ppid], pid)
		}
	}
	var out []int32
	stack := []int32{root}
	seen := map[int32]struct{}{root: {}}
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, c := range children[p] {
			if _, ok := seen[c]; ok {
				continue
			}
			seen[c] = struct{}{}
			out = append(out, c)
			stack = append(stack, c)
		}
	}
	return out
}

// ppidOf reads PPid from /proc/<pid>/status. Returns 0 on any error.
func ppidOf(pid int32) int32 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			f := strings.Fields(line)
			if len(f) == 2 {
				if v, err := strconv.Atoi(f[1]); err == nil {
					return int32(v)
				}
			}
			return 0
		}
	}
	return 0
}

// installDBRule installs a denied DB table name into ak_db_deny_tables and arms
// the pre-op query-block flag, so the kernel refuses a matching outbound COM_QUERY
// before it reaches the server. The table name is lowercased for case-insensitive
// in-kernel matching. slot indexes the fixed-capacity table array.
func (e *BPFEnforcer) installDBRule(r pipeline.KernelRule, slot *int) error {
	if e.dbDenyTablesMap == nil {
		return fmt.Errorf("db-deny-tables map is nil")
	}
	name := strings.ToLower(strings.TrimSpace(r.DBTable))
	if name == "" {
		return fmt.Errorf("db rule %q has no table", r.PolicyName)
	}
	if len(name) > 16 {
		return fmt.Errorf("db table %q exceeds 16-byte in-kernel match limit", name)
	}
	if *slot >= dbDenyTableSlots {
		return fmt.Errorf("db-deny-tables full (%d slots)", dbDenyTableSlots)
	}
	var p dbPat
	p.Len = uint32(len(name))
	copy(p.Pat[:], name)
	key := uint32(*slot)
	if err := e.dbDenyTablesMap.Put(key, p); err != nil {
		return err
	}
	*slot++
	e.armFlag(flagDBBlockArmed)
	e.log.Info("enforce: installed db table pre-op block",
		zap.String("policy", r.PolicyName), zap.String("engine", r.DBEngine),
		zap.String("table", name))
	return nil
}

// installNetRule adds a denied prefix (from rule.CIDR) to the IPv4 or IPv6 LPM
// trie.
func (e *BPFEnforcer) installNetRule(r pipeline.KernelRule) error {
	if e.enforceNetMap == nil {
		return fmt.Errorf("enforce-net map is nil")
	}
	if r.CIDR == "" {
		return fmt.Errorf("network rule %q has no cidr", r.PolicyName)
	}
	_, ipnet, err := net.ParseCIDR(r.CIDR)
	if err != nil {
		return err
	}
	ones, _ := ipnet.Mask.Size()
	if ip4 := ipnet.IP.To4(); ip4 != nil {
		key := lpmKey{prefixLen: uint32(ones)}
		copy(key.addr[:], ip4)
		if err := e.enforceNetMap.Put(key, netBlock); err != nil {
			return err
		}
	} else {
		if e.enforceNet6Map == nil {
			return fmt.Errorf("enforce-net6 map is nil")
		}
		key := lpmKey6{prefixLen: uint32(ones)}
		copy(key.addr[:], ipnet.IP.To16())
		if err := e.enforceNet6Map.Put(key, netBlock); err != nil {
			return err
		}
	}
	e.log.Info("enforce: installed egress block prefix",
		zap.String("policy", r.PolicyName), zap.String("cidr", r.CIDR))
	return nil
}

// lpmKey mirrors struct ak_lpm_key in bpf/maps.bpf.h.
type lpmKey struct {
	prefixLen uint32
	addr      [4]byte
}

// lpmKey6 mirrors struct ak_lpm_key6 in bpf/maps.bpf.h.
type lpmKey6 struct {
	prefixLen uint32
	addr      [16]byte
}

// Apply performs a runtime decision. Block is normally realized pre-op by the
// kernel map; here we handle the post-decision / advisory case. Kill sends SIGKILL
// to the session's root process (and any tracked members).
func (e *BPFEnforcer) Apply(sess *types.AgentSession, d types.Decision, ev *types.SyscallEvent) error {
	switch d.Effect {
	case types.EffectBlock:
		return e.applyBlock(d, ev)
	case types.EffectKill:
		return e.applyKill(sess, d)
	case types.EffectAllow, types.EffectAudit, types.EffectAlert:
		// No kernel action; observation/alerting is the exporter's job.
		return nil
	default:
		e.log.Warn("enforce: unknown effect, no action",
			zap.String("effect", string(d.Effect)))
		return nil
	}
}

func (e *BPFEnforcer) applyBlock(d types.Decision, ev *types.SyscallEvent) error {
	if ev != nil && ev.Category == types.CategoryFile {
		// Try to pre-enforce this exact path for future opens if we can and haven't.
		if e.enforceFileMap != nil && isExactPath(ev.Resource) {
			h := bpf2frame.HashString(ev.Resource)
			e.mu.Lock()
			err := e.addFileOp(h, opBit(ev.Operation))
			e.mu.Unlock()
			if err != nil {
				e.log.Warn("enforce: late file block install failed",
					zap.String("path", ev.Resource), zap.Error(err))
			}
		}
		// The observed open already happened (post-op); kernel map only blocks
		// subsequent opens. This decision is therefore advisory for this event.
		e.log.Info("enforce: file block is advisory for the observed open (kernel blocks subsequent opens)",
			zap.String("policy", d.PolicyName),
			zap.String("resource", ev.Resource))
		return nil
	}
	if ev != nil && ev.Category == types.CategoryNetwork {
		// Install the observed destination IP as an exact deny so subsequent
		// connects to it are pre-blocked in the kernel (socket_connect LSM hook).
		if ip := ipFromResource(ev.Resource); ip != nil {
			if err := e.BlockIP(ip); err != nil {
				e.log.Warn("enforce: install net block failed",
					zap.String("policy", d.PolicyName), zap.String("resource", ev.Resource), zap.Error(err))
				return nil
			}
			e.log.Info("enforce: installed egress block for observed destination (advisory for this connect)",
				zap.String("policy", d.PolicyName), zap.String("ip", ip.String()))
		}
		return nil
	}
	res := ""
	cat := types.Category("")
	if ev != nil {
		res, cat = ev.Resource, ev.Category
	}
	e.log.Warn("enforce: block requested for a category with no pre-op enforcement point",
		zap.String("policy", d.PolicyName),
		zap.String("category", string(cat)),
		zap.String("resource", res))
	return nil
}

// BlockIP installs an exact deny (/32 or /128) for ip into the egress LPM trie,
// so the socket_connect LSM hook pre-blocks connects to it. Idempotent.
func (e *BPFEnforcer) BlockIP(ip net.IP) error {
	return e.setIP(ip, true)
}

// UnblockIP removes a previously installed exact deny for ip (e.g. on DNS TTL
// expiry or policy removal). Idempotent.
func (e *BPFEnforcer) UnblockIP(ip net.IP) error {
	return e.setIP(ip, false)
}

func (e *BPFEnforcer) setIP(ip net.IP, block bool) error {
	if ip4 := ip.To4(); ip4 != nil {
		if e.enforceNetMap == nil {
			return fmt.Errorf("enforce-net map is nil")
		}
		key := lpmKey{prefixLen: 32}
		copy(key.addr[:], ip4)
		if block {
			return e.enforceNetMap.Put(key, netBlock)
		}
		return ignoreMissing(e.enforceNetMap.Delete(key))
	}
	if e.enforceNet6Map == nil {
		return fmt.Errorf("enforce-net6 map is nil")
	}
	key := lpmKey6{prefixLen: 128}
	copy(key.addr[:], ip.To16())
	if block {
		return e.enforceNet6Map.Put(key, netBlock)
	}
	return ignoreMissing(e.enforceNet6Map.Delete(key))
}

// ipFromResource extracts the IP from a network resource string as produced by
// bpf2frame ("addr:port" for IPv4, "[addr]:port" for IPv6).
func ipFromResource(resource string) net.IP {
	host := resource
	if h, _, err := net.SplitHostPort(resource); err == nil {
		host = h
	}
	return net.ParseIP(host)
}

// ignoreMissing swallows ebpf "key does not exist" on idempotent deletes.
func ignoreMissing(err error) error {
	if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (e *BPFEnforcer) applyKill(sess *types.AgentSession, d types.Decision) error {
	if sess == nil {
		return fmt.Errorf("enforce: kill requested with nil session")
	}
	// Collect targets: root PID plus any tracked members, de-duplicated, pid>1.
	targets := make([]int32, 0, 1+len(sess.Members))
	seen := make(map[int32]struct{})
	for _, pid := range append([]int32{sess.RootPID}, sess.Members...) {
		if pid <= 1 { // never signal init/kernel/invalid pids
			continue
		}
		if _, dup := seen[pid]; dup {
			continue
		}
		seen[pid] = struct{}{}
		targets = append(targets, pid)
	}
	if len(targets) == 0 {
		return fmt.Errorf("enforce: kill requested but no valid target pid (root=%d)", sess.RootPID)
	}

	if e.dryRun {
		e.log.Warn("enforce: DRY-RUN kill (no signal sent)",
			zap.String("session", sess.ID),
			zap.String("policy", d.PolicyName),
			zap.Int32s("targets", targets))
		return nil
	}

	var firstErr error
	for _, pid := range targets {
		if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil {
			// ESRCH (process already gone) is benign.
			if err == syscall.ESRCH {
				continue
			}
			e.log.Error("enforce: SIGKILL failed",
				zap.Int32("pid", pid), zap.Error(err))
			if firstErr == nil {
				firstErr = fmt.Errorf("enforce: kill pid %d: %w", pid, err)
			}
			continue
		}
		e.log.Warn("enforce: SIGKILL sent",
			zap.String("session", sess.ID),
			zap.String("policy", d.PolicyName),
			zap.Int32("pid", pid))
	}
	return firstErr
}

// Close best-effort clears the enforce-file entries this enforcer installed.
func (e *BPFEnforcer) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.enforceFileMap == nil {
		e.installed = make(map[uint64]struct{})
		return nil
	}
	for h := range e.installed {
		if err := e.enforceFileMap.Delete(h); err != nil {
			e.log.Debug("enforce: cleanup delete failed", zap.Uint64("hash", h), zap.Error(err))
		}
	}
	if e.enforceDirMap != nil {
		for h := range e.instDir {
			_ = e.enforceDirMap.Delete(h)
		}
	}
	if e.taintFilesMap != nil {
		for h := range e.instTaint {
			_ = e.taintFilesMap.Delete(h)
		}
	}
	for h := range e.instSelf {
		if e.enforceFileMap != nil {
			_ = e.enforceFileMap.Delete(h)
		}
		if e.enforceDirMap != nil {
			_ = e.enforceDirMap.Delete(h)
		}
	}
	e.installed = make(map[uint64]struct{})
	e.instDir = make(map[uint64]struct{})
	e.instTaint = make(map[uint64]struct{})
	e.instSelf = make(map[uint64]struct{})
	return nil
}

// isExactPath reports whether p is a concrete absolute path with no wildcard or
// directory-prefix semantics — i.e. representable as a single exact fnv1a key.
func isExactPath(p string) bool {
	if p == "" {
		return false
	}
	if !strings.HasPrefix(p, "/") {
		return false // not an absolute path
	}
	if strings.HasSuffix(p, "/") {
		return false // directory prefix
	}
	if strings.ContainsAny(p, "*?[") {
		return false // glob / wildcard
	}
	return true
}
