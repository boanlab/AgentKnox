// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"

	"github.com/boanlab/agentknox/internal/archive"
	"github.com/boanlab/agentknox/internal/config"
	"github.com/boanlab/agentknox/internal/correlate"
	"github.com/boanlab/agentknox/internal/enforce"
	"github.com/boanlab/agentknox/internal/export"
	"github.com/boanlab/agentknox/internal/forward"
	"github.com/boanlab/agentknox/internal/pipeline"
	"github.com/boanlab/agentknox/internal/policy"
	"github.com/boanlab/agentknox/internal/resolver"
	"github.com/boanlab/agentknox/internal/rollout"
	"github.com/boanlab/agentknox/internal/semantic"
	"github.com/boanlab/agentknox/internal/sensor"
	"github.com/boanlab/agentknox/internal/session"
	"github.com/boanlab/agentknox/pkg/policyspec"
	"github.com/boanlab/agentknox/pkg/types"
)

// Daemon is the composition root wiring every component (docs/architecture.md §10).
type Daemon struct {
	cfg *config.Config
	log *zap.Logger

	loader    *sensor.Loader
	sysSens   *sensor.SystemSensor
	semSens   *sensor.SemanticSensor
	resolver  *resolver.Resolver
	parser    *semantic.Parser
	sessions  *session.Manager
	correl    *correlate.Engine
	policy    *policy.Engine
	enforcer  pipeline.Enforcer
	exporter  *export.Server
	archiver  *archive.Archiver
	forwarder *forward.Forwarder
	mcp       *mcpDetector
	dnsGuard  *dnsGuard

	dbMu   sync.Mutex
	dbPids map[int32]dbConn // pid -> db engine+endpoint, from observed DB-port connects

	workerMu   sync.Mutex
	workerBins map[string]bool // agent worker binaries already semantically resolved+attached
}

func NewDaemon(cfg *config.Config, log *zap.Logger) (*Daemon, error) {
	d := &Daemon{cfg: cfg, log: log}

	// Exporter first: downstream components emit into it.
	exp, err := export.New(cfg.GRPCAddr, cfg.WALDir, log)
	if err != nil {
		return nil, err
	}
	d.exporter = exp

	// Aggregator forwarder (multi-host): a sink that batches events to a central
	// aggregator when AggregatorAddr is set. Hot-reloaded from the config file.
	d.forwarder = forward.New(cfg.NodeName, cfg.AggregatorAddr, log)
	exp.AddSink(d.forwarder)

	// eBPF loader + sensors.
	tLoad := time.Now()
	ld, err := sensor.Load()
	if err != nil {
		return nil, err
	}
	log.Debug("eBPF collection loaded", zap.Duration("took", time.Since(tLoad)))
	d.loader = ld
	d.sysSens = sensor.NewSystemSensor(ld, log)
	d.semSens = sensor.NewSemanticSensor(ld, log)

	// Userspace components.
	d.resolver = resolver.New(cfg.OffsetDBPath, log)
	d.parser = semantic.New(cfg.CapturePrompts, log)
	d.sessions = session.New(cfg.AgentSignatures, cfg.CgroupParent, log)
	d.sessions.ManageCgroup = cfg.ManageCgroup
	d.correl = correlate.New(log)
	d.policy = policy.New(log)
	exp.SetPolicyProvider(func() any { return d.policy.Summaries() })
	d.archiver = archive.New(cfg.ArchiveDir, log)
	d.mcp = newMCPDetector(ld, log)
	d.dbPids = make(map[int32]dbConn)

	lsm, _ := os.ReadFile("/sys/kernel/security/lsm")
	d.enforcer = enforce.SelectBackend(cfg.EnforcerBackend, string(lsm), enforce.Maps{
		Sessions:       ld.SessionMap(),
		SessionPids:    ld.SessionPidsMap(),
		EnforceFile:    ld.EnforceFileMap(),
		EnforceDir:     ld.EnforceDirMap(),
		EnforceNet:     ld.EnforceNetMap(),
		EnforceNet6:    ld.EnforceNet6Map(),
		Posture:        ld.PostureMap(),
		TaintFiles:     ld.TaintFilesMap(),
		SensitiveFiles: ld.SensitiveFilesMap(),
		Flags:          ld.FlagsMap(),
		DBDenyTables:   ld.DBDenyTablesMap(),
		AgentSigs:      ld.AgentSigsMap(),
	}, cfg.DryRun, log)

	// FQDN enforcement: install/evict resolved IPs as egress blocks on DNS answers.
	d.dnsGuard = newDNSGuard(d.enforcer, d.policy, log)

	// Session lifecycle: onboard on detect, tear down on root exit.
	d.sessions.OnNewSession = d.onNewSession
	d.sessions.OnSessionEnded = d.onSessionEnded
	d.sessions.OnMemberExit = d.onMemberExit
	return d, nil
}

// onNewSession runs when the Session Manager detects a new agent: resolve the
// TLS boundary, attach uprobes, register the cgroup for monitoring+enforcement.
func (d *Daemon) onNewSession(s *types.AgentSession) {
	d.log.Info("agent session detected",
		zap.String("id", s.ID), zap.String("agent", string(s.Agent)), zap.Int32("pid", s.RootPID))

	// Index the launch command line as a prompt before the (slower) resolver runs,
	// so a resource named on argv is recognized as referenced from session start.
	d.indexArgvPrompt(s)

	// Arm enforcement before the semantic resolver, whose ELF resolution can take
	// ~1s on a stripped binary and would otherwise leave the agent unenforced.
	// Monitor registration (sensor, works without LSM): cgroup + pid-tree scoping.
	d.sysSens.RegisterSession(s.CgroupID)
	d.sysSens.RegisterPID(s.RootPID)
	for _, p := range s.Members {
		d.sysSens.RegisterPID(p)
	}
	// Enforce upgrade (enforcer, BPF-LSM only): pins the root pid into
	// ak_session_pids with the enforce flag, so the fork tracepoint propagates
	// enforcement to any child the agent spawns from here on.
	if err := d.enforcer.EnforceSession(s); err != nil {
		d.log.Warn("enforce session", zap.Error(err))
	}
	// Covers an agent reached via a symlink whose resolved binary basename is not
	// a configured signature (Bun/Claude: `claude` -> `versions/2.1.211`): in-kernel
	// bprm arming keys on the resolved filename, so it misses such a launcher.
	// (i) arm every descendant already spawned before detection, and (ii) register
	// the resolved binary basename so a later worker exec under that name arms
	// in-kernel.
	d.armLiveDescendants(s.RootPID)
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", s.RootPID)); err == nil {
		if base := filepath.Base(exe); base != "" && !genericInterpreter[strings.ToLower(base)] {
			d.enforcer.RegisterAgentBinary(base)
		}
	}
	// Provenance-taint execution control: if policy forbids running agent-written
	// code, enable the deny-tainted-code posture for this session.
	if d.policy.WantsTaintedCodeBlock(s.Agent) {
		d.enforcer.SetTaintedCodePosture(s.CgroupID, true)
	}
	// Pre-mark the session's developer secrets so the in-kernel file_open hook arms
	// deny-egress synchronously on read-open, ahead of any same-worker io_uring
	// exfil. Only meaningful when the policy blocks tainted egress.
	if d.policy.WantsTaintedEgressBlock(s.Agent) {
		d.markSensitiveSources(s)
	}

	// Semantic capture (best-effort observability) runs after enforcement is armed.
	// The TLS library may not be mapped yet at exec-detection time: ld.so may still
	// be loading NEEDED libs, or the agent may dlopen it lazily (python ssl, node).
	// If full coverage was not reached, re-resolve a few times as the process runs.
	cov := d.attachSemantic(s, false)
	if d.cfg.SemanticEnabled && cov != types.CoverageFull {
		go d.retryResolve(s, cov)
	}
	d.exporter.UpdateSession(s)
	d.log.Debug("session exported", zap.String("id", s.ID), zap.String("coverage", string(s.Coverage)))
}

// markSensitiveSources pre-marks the session's developer secrets in ak_sensitive_files
// so ak_lsm_file_open arms deny-egress on the reading pid the instant the agent
// read-opens one; the LSM file_open hook fires for io_uring opens as well, unlike
// the syscall tracepoints the reactive pipeline consumes. Scans the agent's working
// directory (bounded) plus the standard home secret locations, once at detection.
func (d *Daemon) markSensitiveSources(s *types.AgentSession) {
	marked := 0
	mark := func(p string) {
		abs, err := filepath.Abs(p)
		if err != nil || !correlate.IsSensitiveSource(abs) {
			return
		}
		if fi, err := os.Stat(abs); err != nil || fi.IsDir() {
			return
		}
		d.enforcer.MarkSensitivePath(abs)
		marked++
	}
	cwd, _ := os.Readlink(fmt.Sprintf("/proc/%d/cwd", s.RootPID))
	if cwd != "" {
		_ = filepath.Walk(cwd, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi == nil {
				return nil
			}
			if fi.IsDir() {
				base := filepath.Base(p)
				if p != cwd && (base == "node_modules" || base == ".git" || base == "vendor" || base == ".cache") {
					return filepath.SkipDir
				}
				if strings.Count(strings.TrimPrefix(p, cwd), string(os.PathSeparator)) > 4 {
					return filepath.SkipDir
				}
				return nil
			}
			mark(p)
			return nil
		})
	}
	// Home secret locations may live outside the working directory. Resolve the agent's
	// HOME from its own environment (the daemon runs as root, so os.UserHomeDir is wrong).
	if home := procEnvHome(s.RootPID); home != "" {
		for _, rel := range []string{
			".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials",
			".netrc", ".kube/config", ".env",
		} {
			mark(filepath.Join(home, rel))
		}
	}
	if marked > 0 {
		d.log.Info("sensitive sources marked for in-kernel read-taint egress arm",
			zap.String("session", s.ID), zap.Int("count", marked))
	}
}

// procEnvHome returns the HOME of a process from its own environment block (the daemon
// runs as root, so its own HOME does not match the agent's).
func procEnvHome(pid int32) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return ""
	}
	for _, kv := range strings.Split(string(b), "\x00") {
		if strings.HasPrefix(kv, "HOME=") {
			return kv[len("HOME="):]
		}
	}
	return ""
}

// head returns the first n characters of s, for compact debug logging.
func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// hasLabel reports whether want is present in labels.
func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

// reArmSweep periodically re-arms every process currently in each active session's
// managed cgroup. The fork tracepoint propagates the enforce tag to children forked
// from an already-armed parent, but a sandbox that spawns its worker through a
// reparent can leave a live member unarmed while it stays in the session's cgroup.
// Re-reading cgroup.procs and calling EnforcePID on each (idempotent) covers that.
func (d *Daemon) reArmSweep(ctx context.Context) {
	t := time.NewTicker(1500 * time.Millisecond)
	defer t.Stop()
	var faults [len(sensor.KernelFaultNames)]uint64
	ticks := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Report kernel enforcement faults (an unresolvable path the hooks had to
			// refuse, an arming write a full map rejected, a taint that could not be
			// stored) as they accrue, so a degraded envelope is visible rather than
			// inferred. Every 20th tick keeps this off the per-event path.
			if ticks++; ticks%20 == 0 {
				if cur, err := d.loader.KernelFaults(); err == nil {
					for i, n := range cur {
						if n > faults[i] {
							d.log.Warn("kernel enforcement fault",
								zap.String("kind", sensor.KernelFaultNames[i]),
								zap.Uint64("since_last", n-faults[i]),
								zap.Uint64("total", n))
						}
					}
					faults = cur
				}
			}
			for _, s := range d.sessions.List() {
				if s.State != types.SessionActive {
					continue
				}
				if s.CgroupPath != "" {
					// Managed dedicated cgroup: re-arm every process in it.
					for _, p := range readCgroupProcs(s.CgroupPath) {
						d.enforcer.EnforcePID(p)
					}
					continue
				}
				// Unmanaged shared cgroup (the Codex-sandbox shape: short-lived
				// helpers share the agent's own cgroup, no managed slice): re-arm the
				// root, tracked members, and any live descendant.
				d.enforcer.EnforcePID(s.RootPID)
				for _, p := range s.Members {
					d.enforcer.EnforcePID(p)
				}
				d.rearmDescendants(s.RootPID)
			}
		}
	}
}

// rearmDescendants re-arms every live process descended from root, without the
// one-shot logging of armLiveDescendants (this runs on the periodic sweep).
func (d *Daemon) rearmDescendants(root int32) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	children := make(map[int32][]int32, len(entries))
	for _, e := range entries {
		pid64, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if ppid := readPPID(int32(pid64)); ppid > 0 {
			children[ppid] = append(children[ppid], int32(pid64))
		}
	}
	seen := map[int32]bool{root: true}
	queue := []int32{root}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, c := range children[p] {
			if seen[c] {
				continue
			}
			seen[c] = true
			d.enforcer.EnforcePID(c)
			queue = append(queue, c)
		}
	}
}

// readCgroupProcs returns the host pids listed in a cgroup v2 cgroup.procs file.
func readCgroupProcs(cgroupPath string) []int32 {
	b, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", cgroupPath, "cgroup.procs"))
	if err != nil {
		return nil
	}
	var pids []int32
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		if p, err := strconv.Atoi(line); err == nil {
			pids = append(pids, int32(p))
		}
	}
	return pids
}

// genericInterpreter is the set of runtime/shell basenames that must never be
// registered as an agent worker binary — arming them would enforce on unrelated
// host processes. An agent whose resolved exe is one of these (e.g. Gemini on
// `node`) is covered by cgroup/pid-tree tracking and same-process re-exec instead.
var genericInterpreter = map[string]bool{
	"node": true, "nodejs": true, "deno": true, "bun": true,
	"python": true, "python3": true, "python2": true,
	"bash": true, "sh": true, "dash": true, "zsh": true, "fish": true,
	"ruby": true, "perl": true, "php": true, "java": true, "dotnet": true,
	"env": true, "sudo": true, "busybox": true,
}

// armLiveDescendants arms every process currently descended from root (a session
// launcher just detected), catching a worker the agent forked in the window before
// userspace arming. It reads the /proc pid->ppid tree once and BFS-walks from root.
func (d *Daemon) armLiveDescendants(root int32) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	children := make(map[int32][]int32, len(entries))
	for _, e := range entries {
		pid64, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if ppid := readPPID(int32(pid64)); ppid > 0 {
			children[ppid] = append(children[ppid], int32(pid64))
		}
	}
	seen := map[int32]bool{root: true}
	queue := []int32{root}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, c := range children[p] {
			if seen[c] {
				continue
			}
			seen[c] = true
			d.sysSens.RegisterPID(c)
			d.enforcer.EnforcePID(c)
			queue = append(queue, c)
		}
	}
	if len(seen) > 1 {
		d.log.Info("enforce: armed pre-detection descendants",
			zap.Int32("root", root), zap.Int("count", len(seen)-1))
	}
}

// readPPID returns the parent pid from /proc/<pid>/stat, parsed after the last ')'
// so a comm field containing spaces or parens does not shift the field offsets.
func readPPID(pid int32) int32 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(b)
	r := strings.LastIndexByte(s, ')')
	if r < 0 || r+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[r+2:])
	if len(fields) < 2 {
		return 0
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return int32(ppid)
}

// indexArgvPrompt pushes the agent's launch command line into the semantic stream
// as a prompt, so any resource named on it is recognized as referenced from the
// moment the session is detected.
func (d *Daemon) indexArgvPrompt(s *types.AgentSession) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", s.RootPID))
	if err != nil || len(b) == 0 {
		return
	}
	text := strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
	if text == "" {
		return
	}
	d.log.Debug("argv prompt indexed", zap.Int32("pid", s.RootPID), zap.String("agent", string(s.Agent)),
		zap.Int("len", len(text)), zap.String("head", head(text, 80)))
	d.correl.PushSemantic(&types.SemanticEvent{
		EventID:   types.NewEventID(),
		Time:      time.Now(),
		Kind:      types.SemPrompt,
		Provider:  "argv",
		SessionID: s.ID,
		Agent:     s.Agent,
		HostPID:   s.RootPID,
		Text:      text,
	})
}

// identityUnvouched reports whether the resolved binary's identity is one no
// known-good reference vouches for, which is what marks a session Tampered.
// Binary identity is a policy input of its own, independent of how much of the
// stream the plan reaches, so it is decided for every build rather than only for
// one that descends as far as the offset-database rung. Two things establish it: a
// build-id absent from a loaded reference set, and a code section already resolved
// under a different build-id. Neither fires when nothing could vouch for the
// binary in the first place (no reference set and no prior sighting), since
// silence is not evidence of tampering.
func identityUnvouched(plan *types.AttachPlan) bool {
	if plan == nil || plan.BuildID == "" || plan.KnownGood {
		return false
	}
	return plan.ReferenceSet || plan.IdentityChanged
}

// attachSemantic runs the resolver for the session and attaches semantic uprobes
// for its recovered plan. When detachFirst is set (a re-resolution), the prior
// uprobes are dropped so a better plan does not stack duplicate probes. Returns
// the coverage reached.
func (d *Daemon) attachSemantic(s *types.AgentSession, detachFirst bool) types.SemanticCoverage {
	plan, err := d.resolver.Resolve(s.RootPID, s.Agent)
	if err != nil {
		d.log.Warn("resolve semantic boundary", zap.Error(err))
		return types.CoverageNone
	}
	if plan == nil {
		return types.CoverageNone
	}
	d.sessions.SetAttachPlan(s.ID, plan)
	d.log.Debug("resolver plan",
		zap.String("session", s.ID), zap.String("agent", string(s.Agent)),
		zap.String("boundary", string(plan.Boundary)), zap.String("tier", string(plan.Tier)),
		zap.String("coverage", string(plan.Coverage)), zap.Any("offset_keys", offsetKeys(plan.Offsets)))
	if identityUnvouched(plan) {
		d.sessions.MarkTampered(s.ID)
		d.log.Warn("agent binary identity is not vouched for; session marked tampered",
			zap.String("session", s.ID), zap.String("build_id", plan.BuildID),
			zap.Bool("identity_changed", plan.IdentityChanged))
	}
	// Coverage reflects actual capture capability: the resolver may recover offsets
	// (plan.Coverage), but if the uprobes fail to attach no plaintext is captured,
	// so report CoverageNone rather than a misleading full/degraded.
	coverage := plan.Coverage
	if d.cfg.SemanticEnabled && plan.Coverage != types.CoverageNone {
		if detachFirst {
			_ = d.semSens.Detach(s.RootPID)
		}
		if err := d.attachWithRetry(s, plan); err != nil {
			d.log.Warn("attach uprobes failed; semantic capture unavailable for session",
				zap.String("session", s.ID), zap.String("boundary", string(plan.Boundary)), zap.Error(err))
			coverage = types.CoverageNone
		}
	}
	d.sessions.SetCoverage(s.ID, coverage)
	if coverage == types.CoverageFull {
		// The plan hooks both directions, but hooking is not reading: the rustls
		// AEAD dispatch and the Node SEA boundary both attach cleanly and deliver
		// no plaintext. Re-check once the session has had a chance to talk, and
		// downgrade if nothing arrived, so a coverage-conditioned rule can fire.
		go d.watchWireCoverage(s.ID)
	}
	return coverage
}

// wireCoverageGrace is how long an attached session has to produce live plaintext
// before its coverage is downgraded. It must exceed a cold agent's first
// model round-trip.
const wireCoverageGrace = 45 * time.Second

// watchWireCoverage downgrades full -> degraded for a session whose boundary
// attached but never yielded plaintext, so that intent is transcript-sourced and
// a rule keyed on coverage can tighten accordingly.
func (d *Daemon) watchWireCoverage(sessionID string) {
	time.Sleep(wireCoverageGrace)
	n, ok := d.sessions.WireIntents(sessionID)
	if !ok || n > 0 {
		return
	}
	d.sessions.SetCoverage(sessionID, types.CoverageDegraded)
	// The exporter keeps a shallow copy of each session, so mutating the
	// manager's struct is not enough: re-publish, or akctl and the audit trail
	// keep reporting the stale "full".
	if s, ok := d.sessions.LookupByID(sessionID); ok && s != nil {
		d.exporter.UpdateSession(s)
	}
	d.log.Info("attached boundary yielded no live plaintext; coverage downgraded to degraded",
		zap.String("session", sessionID),
		zap.Duration("after", wireCoverageGrace))
}

// attachErrRetries is the number of immediate in-place retries for a failed
// uprobe attach (transient perf-event/tracefs failures, or the target's file not
// yet fully mapped). Distinct from retryResolve's slower re-resolution loop.
const attachErrRetries = 3

// attachWithRetry attaches the plan's uprobes, retrying a failed attach a few
// times with short backoff before giving up. A stale probe set from a prior
// attempt is detached before each retry so probes never stack.
func (d *Daemon) attachWithRetry(s *types.AgentSession, plan *types.AttachPlan) error {
	var err error
	for attempt := 0; attempt <= attachErrRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 150 * time.Millisecond)
			if syscall.Kill(int(s.RootPID), 0) != nil {
				return err // process gone; stop retrying
			}
			_ = d.semSens.Detach(s.RootPID)
			d.log.Debug("retrying uprobe attach", zap.String("session", s.ID),
				zap.Int("attempt", attempt), zap.Error(err))
		}
		if err = d.semSens.Attach(s.RootPID, plan); err == nil {
			return nil
		}
	}
	return err
}

// resolveWorkerBinary resolves and attaches the semantic boundary of a session
// member that runs a distinct agent-worker binary, deduplicated per binary path.
// The root's uprobes are bound to the root's binary, so a launcher that re-execs
// into a worker shipped as its own executable leaves the TLS on a binary nothing
// is attached to. Both Node-based agents do this (Gemini's worker child, which is
// where its plaintext actually appears, and Copilot's native SEA), so a session
// member running a distinct binary is resolved and attached in its own right.
// semSens.Attach deduplicates per binary, so this only works on a new one.
func (d *Daemon) resolveWorkerBinary(sessionID string, agent types.AgentKind, pid int32) {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || exe == "" {
		return
	}
	d.workerMu.Lock()
	if d.workerBins == nil {
		d.workerBins = make(map[string]bool)
	}
	seen := d.workerBins[exe]
	d.workerBins[exe] = true
	d.workerMu.Unlock()
	if seen {
		return
	}
	plan, err := d.resolver.Resolve(pid, agent)
	if err != nil || plan == nil || plan.Boundary == types.BoundaryNone {
		return
	}
	if err := d.semSens.Attach(pid, plan); err != nil {
		d.log.Debug("worker binary attach failed", zap.String("exe", exe), zap.Error(err))
		return
	}
	d.sessions.SetAttachPlan(sessionID, plan)
	d.log.Debug("resolved agent worker binary", zap.String("session", sessionID),
		zap.String("exe", exe), zap.String("tier", string(plan.Tier)),
		zap.String("coverage", string(plan.Coverage)))
}

// retryResolve re-resolves and re-attaches the semantic boundary a few times as
// the process runs, so a late-loaded TLS library (ld.so still loading NEEDED
// libs, or a lazy dlopen as in Node/python) or a transient attach failure gets
// another chance. Re-resolution is cheap once a build is cached. Stops at full
// coverage, when the process exits, or when the schedule is exhausted.
func (d *Daemon) retryResolve(s *types.AgentSession, initial types.SemanticCoverage) {
	best := initial
	for _, delay := range []time.Duration{300 * time.Millisecond, 1 * time.Second, 2 * time.Second, 4 * time.Second, 6 * time.Second} {
		time.Sleep(delay)
		if syscall.Kill(int(s.RootPID), 0) != nil {
			return // process gone
		}
		cov := d.attachSemantic(s, true)
		if coverageRank(cov) > coverageRank(best) {
			best = cov
			d.exporter.UpdateSession(s)
			d.log.Info("resolver: coverage upgraded on retry",
				zap.String("id", s.ID), zap.String("coverage", string(cov)))
		}
		if best == types.CoverageFull {
			return
		}
	}
}

// coverageRank orders coverage so re-resolution only upgrades.
func coverageRank(c types.SemanticCoverage) int {
	switch c {
	case types.CoverageFull:
		return 2
	case types.CoverageDegraded:
		return 1
	default:
		return 0
	}
}

// onSessionEnded tears down a session on root exit: detach uprobes, unregister
// the pid tree from monitoring, and drop per-session archive tracking. Cgroup-level
// enforcement (ak_sessions + deny-tainted-code posture) is torn down only when no
// other active session still occupies the cgroup, since a child mis-onboarded as
// its own session shares the agent's managed cgroup.
func (d *Daemon) onSessionEnded(s *types.AgentSession) {
	_ = d.semSens.Detach(s.RootPID)
	if !d.sessions.CgroupHasActiveSession(s.CgroupID, s.ID) {
		d.sysSens.UnregisterSession(s.CgroupID)
		d.enforcer.SetTaintedCodePosture(s.CgroupID, false)
		// Clear any deny-egress posture set for this cgroup while it was tainted.
		// Without this the posture leaks: cgroup ids are recycled by the kernel, so a
		// later agent session reusing the id would start with its egress (including the
		// agent's own model/auth connections) pre-blocked.
		d.enforcer.SetNetPosture(s.CgroupID, false)
	}
	d.sysSens.UnregisterPID(s.RootPID)
	d.mcp.forget(s.RootPID)
	d.forgetDB(s.RootPID)
	for _, p := range s.Members {
		d.sysSens.UnregisterPID(p)
		d.mcp.forget(p)
		d.forgetDB(p)
	}
	d.archiver.SessionEnded(s.ID)
	d.policy.ForgetSession(s.ID)
	d.exporter.UpdateSession(s)
	// Last: the cgroup can only go once its processes are gone and the flags that
	// keyed off it have been cleared.
	d.sessions.ReleaseSessionCgroup(s)
}

// onMemberExit releases the per-pid kernel state of a session member that has
// exited. Session teardown cannot cover this: it walks s.Members, which no
// longer contains a child that already exited, so without this every process the
// agent ever spawned left a permanent entry in the pid map.
func (d *Daemon) onMemberExit(s *types.AgentSession, pid int32) {
	d.sysSens.UnregisterPID(pid)
	d.mcp.forget(pid)
	d.forgetDB(pid)
}

// withAgentHelpers expands the configured agent signatures with the stable helper
// binaries an agent re-execs itself as or delegates work to, so the in-kernel bprm
// arming tags them (with the deny-code flag) at exec, before they touch files. Codex
// performs its file writes (apply_patch) in codex-code-mode-host and its command
// execution in codex-linux-sandbox, out of the codex process tree, so without arming
// their agent writes escape provenance taint.
func withAgentHelpers(sigs []string) []string {
	has := func(s string) bool {
		for _, x := range sigs {
			if strings.EqualFold(strings.TrimSpace(x), s) {
				return true
			}
		}
		return false
	}
	out := append([]string{}, sigs...)
	if has("codex") {
		out = append(out, "codex-linux-sandbox", "codex-code-mode-host")
	}
	return out
}

// anyWantsTaintedCodeBlock reports whether the loaded policy blocks agent-written
// code execution for any supported agent, so the deny-tainted-code session flag can
// be armed before agents exec.
func (d *Daemon) anyWantsTaintedCodeBlock() bool {
	for _, a := range []types.AgentKind{
		types.AgentClaudeCode, types.AgentCodex, types.AgentCrush, types.AgentGemini,
		types.AgentCopilot,
	} {
		if d.policy.WantsTaintedCodeBlock(a) {
			return true
		}
	}
	return false
}

func (d *Daemon) Run(ctx context.Context) error {
	// Reclaim managed cgroups left behind by a previous run (a crash, a kill -9,
	// or a release that hit EBUSY). Only empty ones are removed, so a live
	// session's cgroup is never touched.
	d.sessions.SweepOrphanCgroups()

	// Exporter.Start blocks until ctx is done (it owns the HTTP servers), so run
	// it in the background and let Run proceed to load/attach the sensors.
	go func() {
		if err := d.exporter.Start(ctx); err != nil {
			d.log.Error("exporter", zap.Error(err))
		}
	}()
	t0 := time.Now()
	if err := d.loader.AttachTracepoints(); err != nil {
		return err
	}
	d.log.Debug("attached tracepoints", zap.Duration("took", time.Since(t0)))
	if err := d.loader.AttachKprobes(); err != nil {
		d.log.Info("birth-time task arming unavailable (wake_up_new_task kprobe); "+
			"clone-flavor worker spawns may not be armed", zap.Error(err))
	} else {
		d.log.Debug("attached wake_up_new_task kprobe (birth-time arming)")
	}
	if err := d.loader.AttachIOUring(); err != nil {
		d.log.Info("io_uring observation unavailable (needs the io_uring_submit_req tracepoint, kernel 6.1+)", zap.Error(err))
	} else {
		d.log.Debug("attached io_uring submission tracepoint")
	}
	attached, failed := d.loader.AttachLSM()
	if len(attached) > 0 {
		d.log.Info("attached BPF-LSM enforcement hooks", zap.Strings("hooks", attached))
	}
	for name, err := range failed {
		d.log.Warn("BPF-LSM hook unavailable; the operations it mediates are observed, not refused",
			zap.String("hook", name), zap.Error(err))
	}
	// A lost non-core hook costs one operation. A lost CORE hook voids a whole
	// class of Block decisions, and the rules for it would still be installed into
	// maps that nothing reads, so the backend is demoted to the honest post-hoc one
	// instead of reporting sessions as mapped into an enforcement domain that is
	// not there. The backend is otherwise selected from the active LSM list before
	// attach, which cannot see a hook the kernel declines.
	if missing := sensor.MissingCoreLSM(failed); len(missing) > 0 {
		d.log.Error("core BPF-LSM hooks unavailable; pre-operation enforcement cannot be honored, "+
			"falling back to post-hoc (kill) enforcement",
			zap.Strings("hooks", missing), zap.Strings("attached", attached))
		d.enforcer = enforce.NewUserspace(d.cfg.DryRun, d.log)
		d.dnsGuard = newDNSGuard(d.enforcer, d.policy, d.log)
	}

	// Load policies + install kernel rules, then watch the policy dir for changes.
	d.applyPolicies()

	// Arm the deny-tainted-code session flag when any policy blocks agent-written
	// code, then seed agent signatures so the bprm hook arms a freshly exec'd agent
	// in-kernel with the flag already set and fork-propagated across the agent tree.
	d.enforcer.SetDenyCode(d.anyWantsTaintedCodeBlock())
	d.enforcer.PopulateAgentSigs(withAgentHelpers(d.cfg.AgentSignatures))
	d.installSelfProtection()
	go d.watchPolicies(ctx)

	// Aggregator forwarding + config-file hot-reload of the aggregator target.
	go d.forwarder.Start(ctx)
	go d.watchConfig(ctx)

	// FQDN egress blocks: evict resolved IPs as their TTLs lapse.
	go d.dnsGuard.sweep(ctx)

	sysCh, err := d.sysSens.Start(ctx)
	if err != nil {
		return err
	}
	var semCh <-chan types.SemanticChunk
	if d.cfg.SemanticEnabled {
		if semCh, err = d.semSens.Start(ctx); err != nil {
			d.log.Warn("semantic sensor start", zap.Error(err))
		}
	}
	actCh, edgeCh := d.correl.Outputs()

	// Bootstrap: detect already-running agents (non-blocking; resolving many
	// large agent binaries can take a while, and the API must serve meanwhile).
	go d.scanProc()

	go d.handleSyscalls(sysCh)
	go d.handleSemantic(semCh)
	go d.handleActions(actCh)
	go d.handleEdges(edgeCh)
	// Transcript tailers supply prompts, tool calls and results from each agent's
	// own on-disk session records. They run for every agent regardless of what the
	// wire yields: a parallel content source, not a fallback switched on when
	// uprobe capture fails. The wire adds live plaintext where the boundary
	// carries it, and the session's coverage level records whether it did.
	// Gated by SemanticEnabled alongside the wire sensor, so SemanticEnabled=false
	// leaves the correlator with no semantic events at all and the daemon in
	// syscall-only operation.
	if d.cfg.SemanticEnabled {
		go d.tailCodexRollout(ctx)
		go d.tailClaudeTranscript(ctx)
		go d.tailGeminiTranscript(ctx)
		go d.tailCrushSessions(ctx)
		go d.tailCopilotSessions(ctx)
	}
	go d.reArmSweep(ctx)

	<-ctx.Done()
	d.log.Info("shutting down")
	_ = d.semSens.Close()
	_ = d.sysSens.Close()
	_ = d.enforcer.Close()
	_ = d.loader.Close()
	_ = d.exporter.Close()
	return nil
}

func (d *Daemon) handleSyscalls(ch <-chan types.SyscallEvent) {
	for ev := range ch {
		e := ev
		// Detection & lifecycle.
		if e.Category == types.CategoryProcess && e.Operation == "exec" {
			d.sessions.OnExec(&e)
		}
		d.sessions.Enrich(&e)
		if e.Category == types.CategoryProcess && e.Operation == "exit" {
			d.sessions.OnExit(&e)
		}
		if e.Session == nil {
			continue // not part of a tracked agent session
		}
		// DNS answer: resolve fqdn policy rules to concrete IP egress blocks.
		if e.DNS != nil && len(e.DNS.Answers) > 0 {
			d.dnsGuard.observe(e.DNS)
		}
		// A session member connecting to a DB port: route its captured plaintext
		// to the DB wire parser instead of the JSON reassembler.
		if isConnect(&e) {
			d.noteDBConnect(e.HostPID, e.Resource)
		}
		// Scope enforcement to newly-observed agent-tree processes, and preserve
		// any script/code the agent wrote and is now running.
		if e.Category == types.CategoryProcess && e.Operation == "exec" {
			d.sysSens.RegisterPID(e.HostPID)
			d.enforcer.EnforcePID(e.HostPID)
			// A session member that execs a distinct agent-worker binary needs its own
			// semantic resolve+attach: the root's uprobes are bound to the root's binary
			// (the Copilot shape, where a Node launcher spawns a native SEA worker owning
			// the TLS connections); a no-op for same-binary re-execs and non-agent children.
			if d.sessions.AgentOf(e.HostPID) == e.Session.Agent {
				d.resolveWorkerBinary(e.Session.SessionID, e.Session.Agent, e.HostPID)
			}
			// A session child with pipe stdin+stdout may be a stdio MCP server;
			// register its pipes so JSON-RPC is captured at the pipe boundary.
			d.mcp.consider(e.HostPID)
			go d.archiver.OnExec(e.Session.SessionID, e.HostPID, e.Resource)
			// Interpreter-script disguise (`python data.txt`): kernel bprm sees only the
			// interpreter, so resolve the script argument in userspace and Kill if it is
			// agent-written code (the BPF verifier's instruction budget precludes doing
			// the argv+cwd resolution in-kernel).
			ev := e
			go d.checkInterpreterScript(&ev)
		}
		// Track files the agent writes (so we can archive them if later executed),
		// and provenance-taint them so execution can be blocked. Every write gets
		// content-agnostic WRITTEN taint (blocks direct exec); code is additionally
		// flagged (blocks interpreter read). chmod +x also flags code.
		if e.Category == types.CategoryFile && e.Operation == "write" {
			d.archiver.NoteWrite(e.Session.SessionID, e.Resource, e.Time)
			if d.policy.WantsTaintedCodeBlock(e.Session.Agent) {
				d.enforcer.TaintFile(e.Resource, detectCode(e.Resource))
			}
			// Persistence artifact (cron/systemd/hook): mark it so a later
			// out-of-tree execution by cron/systemd is detected and attributed.
			if isPersistencePath(e.Resource) {
				d.enforcer.TaintPersist(e.Resource)
			}
		}
		if e.Category == types.CategoryFile && e.Operation == "chmod" {
			if d.policy.WantsTaintedCodeBlock(e.Session.Agent) && hasExecBit(e.Resource) {
				d.enforcer.TaintFile(e.Resource, true)
			}
		}
		sess := d.sessionByID(e.Session.SessionID)
		if sess == nil {
			sess, _ = d.sessions.LookupByCgroup(e.CgroupID)
		}
		dec := d.policy.EvaluateSyscall(&e, sess)
		d.act(sess, dec, &e)
		d.correl.PushSyscall(&e)
		d.exporter.EmitSyscall(&e)
	}
}

func (d *Daemon) handleSemantic(ch <-chan types.SemanticChunk) {
	if ch == nil {
		return
	}
	for chunk := range ch {
		// Attribute by exact producing pid first: a semantic chunk carries the
		// precise process that did the TLS op, which distinguishes co-resident
		// agents that share a cgroup (e.g. launched from one shell without managed
		// cgroups). Fall back to the cgroup when the pid is not a tracked member.
		sess, _ := d.sessions.LookupByPID(chunk.HostPID)
		if sess == nil {
			sess, _ = d.sessions.LookupByCgroup(chunk.CgroupID)
		}
		var events []types.SemanticEvent
		if db, ok := d.dbEngine(chunk.HostPID); ok {
			events = d.parser.FeedDB(chunk, sess, db.engine) // binary DB wire, not JSON
			for i := range events {
				if events[i].DBQuery != nil {
					events[i].DBQuery.Endpoint = db.endpoint
				}
			}
		} else {
			events = d.parser.Feed(chunk, sess)
		}
		if sess != nil && len(events) > 0 {
			// These came off the live plaintext boundary, not the transcript:
			// this is what makes the session's coverage genuinely "full".
			d.sessions.NoteWireIntent(sess.ID)
		}
		sawMCP := false
		for _, sem := range events {
			s := sem
			if s.Kind == types.SemMCP {
				sawMCP = true
			}
			dec := d.policy.EvaluateSemantic(&s, sess)
			if dec.Effect != types.EffectAllow {
				d.exporter.EmitAlert(&types.Alert{
					AlertID: s.EventID, Time: time.Now(), SessionID: s.SessionID,
					Agent: s.Agent, Severity: sev(dec.Effect), Effect: dec.Effect,
					PolicyName: dec.PolicyName, Reason: dec.Reason, Semantic: &s,
				})
				// Apply a semantic-layer Block/Kill directly: the decision keys on parsed
				// content (a tool_use, MCP method, or database query) the system layer
				// cannot see. Kill terminates the offending agent; Block additionally arms
				// the deny-egress posture so a follow-on connection is pre-blocked.
				if sess != nil && (dec.Effect == types.EffectBlock || dec.Effect == types.EffectKill) {
					_ = d.enforcer.Apply(sess, dec, nil)
					if dec.Effect == types.EffectBlock {
						d.enforcer.SetNetPosture(sess.CgroupID, true)
					}
				}
			}
			d.correl.PushSemantic(&s)
			d.exporter.EmitSemantic(&s)
		}
		// Behavioral confirmation of stdio-MCP candidates: keep pipes that yield
		// JSON-RPC, evict those that never do.
		d.mcp.noteChunk(chunk.HostPID, sawMCP)
	}
}

// tailCodexRollout tails Codex session transcripts (see package rollout). Codex
// resolves an AEAD-assembly boundary, but on a host whose AES-GCM dispatches to
// the VAES/AVX-512 stitched path the register layout differs from the one the
// handler reads, so no clean plaintext comes off the wire and this transcript is
// the only content source. No-op when no Codex sessions dir exists.
func (d *Daemon) tailCodexRollout(ctx context.Context) {
	dir := rollout.SessionsDir()
	if dir == "" {
		return
	}
	if _, err := os.Stat(dir); err != nil {
		return // Codex not installed / no sessions yet
	}
	d.log.Info("tailing codex rollout transcripts", zap.String("dir", dir))
	rollout.NewTailer(dir, d.log).Watch(ctx, d.emitRolloutItems)
}

// tailClaudeTranscript tails Claude Code project transcripts (see
// rollout/claude.go), the structured record of the same exchange the wire
// carries. Claude's embedded stripped BoringSSL resolves by prologue signature
// and does yield live plaintext, so this runs alongside wire capture rather
// than in place of it. No-op when no Claude projects dir exists.
func (d *Daemon) tailClaudeTranscript(ctx context.Context) {
	for _, dir := range rollout.ClaudeProjectDirs() {
		d.log.Info("tailing claude code transcripts", zap.String("dir", dir))
		go rollout.NewTailerWith(dir, d.log, rollout.ClaudeMatch, rollout.ParseClaudeLine).Watch(ctx, d.emitClaudeItems)
	}
}

// tailGeminiTranscript tails Gemini CLI chat transcripts (see rollout/gemini.go).
// Gemini's Node bundle exports SSL_* in .dynsym and does yield live plaintext, so
// this runs alongside wire capture. No-op when no Gemini transcript dir exists.
func (d *Daemon) tailGeminiTranscript(ctx context.Context) {
	for _, dir := range rollout.GeminiTranscriptDirs() {
		d.log.Info("tailing gemini cli transcripts", zap.String("dir", dir))
		go rollout.NewTailerWith(dir, d.log, rollout.GeminiMatch, rollout.ParseGeminiLine).Watch(ctx, d.emitGeminiItems)
	}
}

// tailCopilotSessions tails GitHub Copilot CLI session event logs. The SEA
// exports SSL_read/SSL_write, so a boundary resolves, but it is off the data
// path: those hooks fire zero times during a real API call because the
// TLS/HTTP2/SSE stack runs as JavaScript and WASM inside V8, where no static ELF
// function holds the plaintext. This transcript is the only content source, with
// enforcement on the system layer.
func (d *Daemon) tailCopilotSessions(ctx context.Context) {
	for _, dir := range rollout.CopilotSessionDirs() {
		d.log.Info("tailing copilot cli transcripts", zap.String("dir", dir))
		go rollout.NewTailerWith(dir, d.log, rollout.CopilotMatch, rollout.ParseCopilotLine).Watch(ctx, d.emitCopilotItems)
	}
}

// tailCrushSessions polls Crush's per-project SQLite session stores (see
// rollout/crush.go). Crush ships `-s`-stripped, with no crypto/tls symbols in
// .symtab, but the Go runtime function table in .gopclntab still names
// crypto/tls.(*Conn).Read/Write, so the resolver recovers the boundary and the
// wire yields live plaintext; this store runs alongside it.
func (d *Daemon) tailCrushSessions(ctx context.Context) {
	rollout.NewCrushReader(d.log).Watch(ctx, d.emitCrushItems)
}

// emitRolloutItems feeds Codex transcript items through the shared semantic path.
func (d *Daemon) emitRolloutItems(_ string, items []rollout.Item) {
	d.emitTranscriptItems(items, "codex-rollout", d.latestCodexSession(), types.AgentCodex)
}

// emitClaudeItems feeds Claude transcript items through the shared semantic path
// (see emitToAgentSessions for the fan-out attribution rationale).
func (d *Daemon) emitClaudeItems(_ string, items []rollout.Item) {
	d.emitToAgentSessions(items, "claude-transcript", types.AgentClaudeCode)
}

// emitGeminiItems feeds Gemini transcript items through the shared semantic path.
func (d *Daemon) emitGeminiItems(_ string, items []rollout.Item) {
	d.emitToAgentSessions(items, "gemini-transcript", types.AgentGemini)
}

func (d *Daemon) emitCopilotItems(_ string, items []rollout.Item) {
	d.emitToAgentSessions(items, "copilot-transcript", types.AgentCopilot)
}

// emitCrushItems feeds Crush session-store items through the shared semantic path.
func (d *Daemon) emitCrushItems(_ string, items []rollout.Item) {
	d.emitToAgentSessions(items, "crush-transcript", types.AgentCrush)
}

// emitToAgentSessions attributes transcript items to every active session of the
// given agent kind. A single invocation of these agents fans out into many
// signature-matched processes tracked as their own sessions, while the transcript
// is one conversation, so the model's declared intent is made visible to whichever
// session actually performs a syscall.
func (d *Daemon) emitToAgentSessions(items []rollout.Item, provider string, kind types.AgentKind) {
	sessions := d.sessionsOf(kind)
	if len(sessions) == 0 {
		d.emitTranscriptItems(items, provider, nil, kind)
		return
	}
	for _, sess := range sessions {
		d.emitTranscriptItems(items, provider, sess, kind)
	}
}

// emitTranscriptItems converts parsed transcript items into semantic events,
// attributes them to the given active session, and runs them through the same
// policy/correlation/export path as TLS-captured events.
func (d *Daemon) emitTranscriptItems(items []rollout.Item, provider string, sess *types.AgentSession, defaultAgent types.AgentKind) {
	for _, it := range items {
		ev := types.SemanticEvent{
			EventID:     types.NewEventID(),
			Time:        it.Time,
			TimestampNS: uint64(it.Time.UnixNano()),
			Kind:        it.Kind,
			Provider:    provider,
		}
		if sess != nil {
			ev.SessionID, ev.Agent, ev.HostPID, ev.CgroupID = sess.ID, sess.Agent, sess.RootPID, sess.CgroupID
		} else {
			ev.Agent = defaultAgent
		}
		switch it.Kind {
		case types.SemToolUse:
			ev.ToolUse = it.ToolUse
			if !d.cfg.CapturePrompts && ev.ToolUse != nil {
				ev.ToolUse.Input = nil
				ev.Redacted = true
			}
		case types.SemToolResult:
			ev.ToolResult = it.ToolResult
			ev.Text, ev.Redacted = d.applyCapture(it.Text)
		default:
			ev.Text, ev.Redacted = d.applyCapture(it.Text)
		}
		dec := d.policy.EvaluateSemantic(&ev, sess)
		if dec.Effect != types.EffectAllow {
			d.exporter.EmitAlert(&types.Alert{
				AlertID: ev.EventID, Time: time.Now(), SessionID: ev.SessionID,
				Agent: ev.Agent, Severity: sev(dec.Effect), Effect: dec.Effect,
				PolicyName: dec.PolicyName, Reason: dec.Reason, Semantic: &ev,
			})
		}
		d.correl.PushSemantic(&ev)
		d.exporter.EmitSemantic(&ev)
	}
}

// applyCapture returns text as-is when prompt capture is enabled, else a redacted
// placeholder (mirrors the semantic parser's policy for TLS-captured text).
func (d *Daemon) applyCapture(text string) (string, bool) {
	if d.cfg.CapturePrompts || text == "" {
		return text, false
	}
	return fmt.Sprintf("<redacted:%d chars>", len(text)), true
}

// latestCodexSession returns the most recently started active Codex session, or
// nil if none is tracked.
func (d *Daemon) latestCodexSession() *types.AgentSession {
	return d.latestSessionOf(types.AgentCodex)
}

// sessionsOf returns every active session of the given agent kind.
func (d *Daemon) sessionsOf(kind types.AgentKind) []*types.AgentSession {
	var out []*types.AgentSession
	for _, s := range d.sessions.List() {
		if s.Agent == kind {
			out = append(out, s)
		}
	}
	return out
}

// latestSessionOf returns the most recently started active session of the given
// agent kind, or nil.
func (d *Daemon) latestSessionOf(kind types.AgentKind) *types.AgentSession {
	var best *types.AgentSession
	for _, s := range d.sessions.List() {
		if s.Agent != kind {
			continue
		}
		if best == nil || s.StartTime.After(best.StartTime) {
			best = s
		}
	}
	return best
}

func (d *Daemon) handleActions(ch <-chan types.CorrelatedAction) {
	for a := range ch {
		act := a
		sess, _ := d.sessions.LookupByCgroup(0)
		if act.SessionID != "" {
			for _, s := range d.sessions.List() {
				if s.ID == act.SessionID {
					sess = s
					break
				}
			}
		}
		dec := d.policy.EvaluateAction(&act, sess)
		// Arm-at-taint: the instant a session becomes exfil-tainted by a sensitive
		// read, pre-arm the deny-egress posture so the follow-on connect is refused
		// pre-operation in the kernel. Gated on a policy that would Block/Kill a
		// tainted connect, so a benign sensitive read never severs a session's egress.
		if sess != nil && hasLabel(act.Taint, "sensitive") &&
			d.policy.WantsTaintedEgressBlock(sess.Agent) {
			d.enforcer.SetNetPosture(sess.CgroupID, true)
			// Also fork-propagate the deny from the exact tainting process, so an
			// exfil child (e.g. a `curl` a node worker spawns) is refused even when it
			// runs in a different cgroup than the session's (the per-cgroup posture above
			// misses that case).
			d.enforcer.SetPidEgressDeny(act.HostPID)
		}
		if dec.Effect != types.EffectAllow || act.Mismatch {
			d.exporter.EmitAlert(&types.Alert{
				AlertID: act.ActionID, Time: time.Now(), SessionID: act.SessionID,
				Severity: sev(dec.Effect), Effect: dec.Effect,
				PolicyName: dec.PolicyName, Reason: dec.Reason, Action: &act,
			})
			if sess != nil {
				_ = d.enforcer.Apply(sess, dec, nil)
				// Pre-block escalation: once a session is caught exfiltrating (tainted
				// egress / intent-effect mismatch under a Block/Kill verdict), install
				// a deny-all-egress kernel posture so subsequent connects are pre-blocked.
				if (dec.Effect == types.EffectBlock || dec.Effect == types.EffectKill) &&
					(len(act.Taint) > 0 || act.Mismatch) {
					d.enforcer.SetNetPosture(sess.CgroupID, true)
				}
			}
		}
		d.exporter.EmitAction(&act)
	}
}

func (d *Daemon) handleEdges(ch <-chan types.GraphEdge) {
	for e := range ch {
		edge := e
		d.exporter.EmitEdge(&edge)
	}
}

// act applies a per-syscall decision.
func (d *Daemon) act(sess *types.AgentSession, dec types.Decision, ev *types.SyscallEvent) {
	if dec.Effect == types.EffectAllow || dec.Effect == types.EffectAudit {
		return
	}
	if sess != nil {
		_ = d.enforcer.Apply(sess, dec, ev)
	}
	if dec.Effect != types.EffectAudit {
		var agent types.AgentKind
		if sess != nil {
			agent = sess.Agent
		}
		d.exporter.EmitAlert(&types.Alert{
			AlertID: ev.EventID, Time: time.Now(), SessionID: sidOf(sess),
			Agent: agent, Severity: sev(dec.Effect), Effect: dec.Effect,
			PolicyName: dec.PolicyName, Reason: dec.Reason, Syscall: ev,
		})
	}
}

// installSelfProtection forbids enforce-mode agents from tampering with
// AgentKnox's own binary, config, policy dir, WAL, and archive (BPF-LSM backend
// only; the daemon is self-excluded so it can still manage them).
func (d *Daemon) installSelfProtection() {
	be, ok := d.enforcer.(*enforce.BPFEnforcer)
	if !ok {
		return // userspace backend cannot self-protect in-kernel
	}
	var files, dirs []string
	if d.cfg.File != "" {
		files = append(files, d.cfg.File)
	}
	if exe, err := os.Executable(); err == nil {
		files = append(files, exe)
	}
	if d.cfg.OffsetDBPath != "" {
		files = append(files, d.cfg.OffsetDBPath)
	}
	for _, dir := range []string{d.cfg.PolicyDir, d.cfg.WALDir, d.cfg.ArchiveDir} {
		if dir != "" {
			dirs = append(dirs, dir)
		}
	}
	be.InstallSelfProtection(files, dirs)
}

// applyPolicies loads the policy directory, compiles it, and (re)installs the
// pre-enforceable kernel rules. Safe to call repeatedly (hot-reload): it clears
// the previously installed rules first. Session flags and provenance taint are
// preserved across reloads.
func (d *Daemon) applyPolicies() {
	dir := d.cfg.PolicyDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		d.log.Info("no policy dir; running observe-only", zap.String("dir", dir))
		return
	}
	var policies []*policyspec.Policy
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		p, err := policyspec.LoadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			d.log.Warn("policy load", zap.String("file", e.Name()), zap.Error(err))
			continue
		}
		policies = append(policies, p)
	}
	if err := d.policy.Load(policies); err != nil {
		d.log.Warn("policy compile", zap.Error(err))
		return
	}
	if err := d.enforcer.ClearRules(); err != nil {
		d.log.Warn("clear kernel rules", zap.Error(err))
	}
	if err := d.enforcer.InstallRules(d.policy.KernelRules()); err != nil {
		// A rule that never reached the kernel is not enforced pre-operation, so a
		// partial install is an error rather than a note: the envelope in force is
		// narrower than the policy that was just loaded.
		d.log.Error("install kernel rules", zap.Error(err))
	}
	// Re-arm provenance for the policy just loaded. The in-kernel taint writer is
	// gated on the deny-tainted-code flag, so a provenance rule added at runtime is
	// inert until the flag is re-derived and the agent signatures are re-seeded with
	// it; without this, a hot-reloaded provenance rule silently never takes effect.
	d.enforcer.SetDenyCode(d.anyWantsTaintedCodeBlock())
	d.enforcer.PopulateAgentSigs(withAgentHelpers(d.cfg.AgentSignatures))
	// Re-apply the deny-tainted-code posture and session flags for active sessions
	// whose agent is now (or no longer) covered by a tainted-code-block rule.
	for _, s := range d.sessions.List() {
		if s.State != types.SessionActive {
			continue
		}
		d.enforcer.SetTaintedCodePosture(s.CgroupID, d.policy.WantsTaintedCodeBlock(s.Agent))
		if err := d.enforcer.EnforceSession(s); err != nil {
			d.log.Warn("re-arm session after policy reload", zap.String("session", s.ID), zap.Error(err))
		}
	}
	d.log.Info("policies loaded", zap.Int("count", len(policies)))
}

// watchPolicies hot-reloads the policy directory on change (fsnotify), debounced.
func (d *Daemon) watchPolicies(ctx context.Context) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		d.log.Warn("policy watcher unavailable; hot-reload disabled", zap.Error(err))
		return
	}
	defer w.Close()
	if err := w.Add(d.cfg.PolicyDir); err != nil {
		d.log.Info("policy dir not watchable; hot-reload disabled",
			zap.String("dir", d.cfg.PolicyDir), zap.Error(err))
		return
	}
	d.log.Info("watching policy dir for changes", zap.String("dir", d.cfg.PolicyDir))
	var timer *time.Timer
	debounced := make(chan struct{}, 1)
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-w.Events:
			if !strings.HasSuffix(ev.Name, ".yaml") {
				continue
			}
			if timer != nil {
				timer.Stop()
			}
			timer = time.AfterFunc(500*time.Millisecond, func() {
				select {
				case debounced <- struct{}{}:
				default:
				}
			})
		case <-debounced:
			d.log.Info("policy change detected; reloading")
			d.applyPolicies()
		case err := <-w.Errors:
			d.log.Warn("policy watcher error", zap.Error(err))
		}
	}
}

// watchConfig watches the config file and hot-applies the aggregator target on
// change (edit `aggregatorURL` in agentknox.yaml → forwarding starts/stops/
// redirects without a restart). Other config keys still require a restart.
func (d *Daemon) watchConfig(ctx context.Context) {
	if d.cfg.File == "" {
		return
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return
	}
	defer w.Close()
	// Watch the containing dir (editors replace files, which breaks a file watch).
	dir := filepath.Dir(d.cfg.File)
	if err := w.Add(dir); err != nil {
		return
	}
	d.log.Info("watching config for aggregator changes", zap.String("file", d.cfg.File))
	base := filepath.Base(d.cfg.File)
	var timer *time.Timer
	reload := make(chan struct{}, 1)
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-w.Events:
			if filepath.Base(ev.Name) != base {
				continue
			}
			if timer != nil {
				timer.Stop()
			}
			timer = time.AfterFunc(500*time.Millisecond, func() {
				select {
				case reload <- struct{}{}:
				default:
				}
			})
		case <-reload:
			nc, err := config.Reload()
			if err != nil {
				d.log.Warn("config reload failed", zap.Error(err))
				continue
			}
			if nc.AggregatorAddr != d.cfg.AggregatorAddr {
				d.log.Info("aggregator target changed",
					zap.String("old", d.cfg.AggregatorAddr), zap.String("new", nc.AggregatorAddr))
				d.cfg.AggregatorAddr = nc.AggregatorAddr
				d.forwarder.SetTarget(nc.AggregatorAddr)
			}
		case <-w.Errors:
		}
	}
}

// scanProc synthesizes exec events for already-running agent processes so the
// daemon adopts sessions that started before it (zero-miss bootstrap).
func (d *Daemon) scanProc() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err != nil {
			continue
		}
		ev := types.SyscallEvent{
			HostPID: int32(pid), PID: int32(pid),
			Category: types.CategoryProcess, Operation: "exec",
			ExePath: exe, Resource: exe,
		}
		d.sessions.OnExec(&ev)
	}
}

func (d *Daemon) sessionByID(id string) *types.AgentSession {
	if id == "" {
		return nil
	}
	for _, s := range d.sessions.List() {
		if s.ID == id {
			return s
		}
	}
	return nil
}

func sidOf(s *types.AgentSession) string {
	if s == nil {
		return ""
	}
	return s.ID
}

// codeExts are file extensions treated as executable code for provenance taint.
var codeExts = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".mjs": true, ".cjs": true,
	".sh": true, ".bash": true, ".zsh": true, ".rb": true, ".pl": true,
	".php": true, ".r": true, ".lua": true, ".ps1": true,
}

// detectCode decides whether an agent-written file is executable code, using
// multiple signals (not just extension, which is trivially evadable): file
// extension OR a shebang OR the executable permission bit.
func detectCode(path string) bool {
	if codeExts[strings.ToLower(filepath.Ext(path))] {
		return true
	}
	if hasShebang(path) {
		return true
	}
	return hasExecBit(path)
}

func hasShebang(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var b [2]byte
	n, _ := f.Read(b[:])
	return n == 2 && b[0] == '#' && b[1] == '!'
}

func hasExecBit(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Mode().Perm()&0o111 != 0
}

// persistencePrefixes are directories whose contents auto-execute out-of-band
// (cron, systemd, at, init) — an agent writing here is registering execution
// that would otherwise run outside its process tree.
var persistencePrefixes = []string{
	"/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/", "/etc/cron.weekly/",
	"/etc/cron.monthly/", "/var/spool/cron/", "/var/spool/at/",
	"/etc/systemd/system/", "/lib/systemd/system/", "/usr/lib/systemd/system/",
	"/etc/init.d/", "/etc/rc.local",
}

// persistenceSuffixes catch per-user and per-repo persistence not pinned to a
// fixed absolute prefix (user systemd units, shell rc files, git hooks).
var persistenceSuffixes = []string{
	"/.config/systemd/user/", "/.bashrc", "/.bash_profile", "/.profile",
	"/.zshrc", "/.config/autostart/", "/.git/hooks/",
}

// isPersistencePath reports whether an absolute path is a persistence artifact
// location (see persistencePrefixes / persistenceSuffixes).
func isPersistencePath(path string) bool {
	if path == "" || path[0] != '/' {
		return false
	}
	for _, p := range persistencePrefixes {
		if strings.HasPrefix(path, p) || path == strings.TrimRight(p, "/") {
			return true
		}
	}
	for _, s := range persistenceSuffixes {
		if strings.Contains(path, s) {
			return true
		}
	}
	return false
}

var interpreterNames = map[string]bool{
	"python": true, "python3": true, "python2": true, "node": true, "bun": true,
	"deno": true, "ts-node": true, "tsx": true, "bash": true, "sh": true,
	"zsh": true, "dash": true, "ruby": true, "perl": true, "php": true, "Rscript": true,
}

// checkInterpreterScript resolves an interpreter's script argument and, if it is
// agent-written code under the deny-tainted-code posture, kills the process.
func (d *Daemon) checkInterpreterScript(e *types.SyscallEvent) {
	sess := d.sessionByID(e.Session.SessionID)
	if sess == nil || !d.policy.WantsTaintedCodeBlock(sess.Agent) {
		return
	}
	interp, script := resolveScriptArg(e.HostPID)
	if !interp || script == "" {
		return
	}
	if !d.enforcer.IsTaintedWritten(script) {
		return
	}
	// Name the operator's rule rather than a literal. The effect stays Kill: the
	// kernel could not resolve the script argument, so the read has already been
	// allowed and a Block has nothing left to refuse.
	now := time.Now()
	matched := d.policy.EvaluateProvenance("agent-code", "exec", script, sess, now)
	name := matched.PolicyName
	if name == "" {
		name = "provenance-taint"
	}
	dec := types.Decision{
		Effect: types.EffectKill, Mode: types.EnforcePost,
		PolicyName: name, Time: now,
		Reason: "interpreter running agent-written code: " + script,
	}
	_ = d.enforcer.Apply(sess, dec, e)
	d.exporter.EmitAlert(&types.Alert{
		AlertID: e.EventID, Time: time.Now(), SessionID: sess.ID, Agent: sess.Agent,
		Severity: "critical", Effect: types.EffectKill,
		PolicyName: dec.PolicyName, Reason: dec.Reason, Syscall: e,
	})
}

// resolveScriptArg reads /proc/<pid>/cmdline; if it is an interpreter invocation,
// it returns the script argument resolved to an absolute path (via /proc cwd).
func resolveScriptArg(pid int32) (isInterp bool, script string) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(b) == 0 {
		return false, ""
	}
	var argv []string
	for _, p := range strings.Split(strings.TrimRight(string(b), "\x00"), "\x00") {
		if p != "" {
			argv = append(argv, p)
		}
	}
	if len(argv) < 2 || !interpreterNames[filepath.Base(argv[0])] {
		return false, ""
	}
	var arg string
	for _, a := range argv[1:] {
		if !strings.HasPrefix(a, "-") {
			arg = a
			break
		}
	}
	if arg == "" {
		return true, ""
	}
	if filepath.IsAbs(arg) {
		return true, filepath.Clean(arg)
	}
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil || cwd == "" {
		return true, ""
	}
	return true, filepath.Clean(filepath.Join(cwd, arg))
}

func sev(e types.PolicyEffect) string {
	switch e {
	case types.EffectKill, types.EffectBlock:
		return "critical"
	case types.EffectAlert:
		return "warn"
	default:
		return "info"
	}
}

// offsetKeys returns sorted "key=0xoffset" pairs of an offset map (diagnostics).
func offsetKeys(m map[string]uint64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		keys[i] = fmt.Sprintf("%s=0x%x", k, m[k])
	}
	return keys
}
