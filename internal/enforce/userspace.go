// SPDX-License-Identifier: Apache-2.0
package enforce

import (
	"net"
	"strings"
	"sync"
	"syscall"

	"go.uber.org/zap"

	"github.com/boanlab/agentknox/internal/bpf2frame"
	"github.com/boanlab/agentknox/internal/pipeline"
	"github.com/boanlab/agentknox/pkg/types"
)

// UserspaceEnforcer is the fallback backend for kernels without BPF-LSM. It
// cannot pre-block operations in the kernel; its repertoire is alert + kill:
// Kill decisions terminate the offending process/session (SIGKILL), Block
// decisions degrade to alerts. This is post-hoc (the observed operation already
// occurred) but honest — unlike out-of-band AppArmor profiles, which cannot
// confine already-running processes.
type UserspaceEnforcer struct {
	dryRun bool
	log    *zap.Logger

	mu    sync.Mutex
	taint map[uint64]uint32 // HashString(path) -> taint bits (in-process, no kernel map)
}

var _ pipeline.Enforcer = (*UserspaceEnforcer)(nil)

func NewUserspace(dryRun bool, log *zap.Logger) *UserspaceEnforcer {
	if log == nil {
		log = zap.NewNop()
	}
	return &UserspaceEnforcer{dryRun: dryRun, log: log, taint: make(map[uint64]uint32)}
}

func (u *UserspaceEnforcer) Backend() string { return "userspace" }

// InstallRules is a no-op: there are no kernel maps. Enforcement is applied
// per-event via Apply (the policy engine still evaluates every event/action).
func (u *UserspaceEnforcer) InstallRules(rules []pipeline.KernelRule) error {
	u.log.Info("enforce(userspace): pre-enforcement unavailable without BPF-LSM; "+
		"policy is enforced post-hoc via process termination",
		zap.Int("rules", len(rules)))
	return nil
}

func (u *UserspaceEnforcer) Close() error                                   { return nil }
func (u *UserspaceEnforcer) ClearRules() error                              { return nil }
func (u *UserspaceEnforcer) EnforceSession(sess *types.AgentSession) error  { return nil }
func (u *UserspaceEnforcer) PopulateAgentSigs(signatures []string)          {}
func (u *UserspaceEnforcer) RegisterAgentBinary(name string)                {}
func (u *UserspaceEnforcer) EnforcePID(pid int32)                           {}
func (u *UserspaceEnforcer) SetPidEgressDeny(pid int32)                     {}
func (u *UserspaceEnforcer) MarkSensitivePath(path string)                  {}
func (u *UserspaceEnforcer) SetNetPosture(cgroupID uint64, deny bool)       {}
func (u *UserspaceEnforcer) SetTaintedCodePosture(cgroupID uint64, en bool) {}
func (u *UserspaceEnforcer) SetDenyCode(en bool)                            {}

// BlockIP/UnblockIP are no-ops without BPF-LSM: egress cannot be pre-blocked in
// the kernel, so network policy degrades to alert + kill (see Apply).
func (u *UserspaceEnforcer) BlockIP(ip net.IP) error   { return nil }
func (u *UserspaceEnforcer) UnblockIP(ip net.IP) error { return nil }

// TaintFile records provenance taint in-process (there is no kernel map here).
func (u *UserspaceEnforcer) TaintFile(path string, code bool) {
	if !isExactPath(path) {
		return
	}
	bits := taintWritten
	if code {
		bits |= taintCode
	}
	h := bpf2frame.HashString(path)
	u.mu.Lock()
	u.taint[h] |= bits
	u.mu.Unlock()
}

// TaintPersist is a no-op for the userspace backend: attribution of out-of-tree
// delayed execution requires the in-kernel bprm hook.
func (u *UserspaceEnforcer) TaintPersist(path string) {}

func (u *UserspaceEnforcer) IsTaintedWritten(path string) bool {
	if !isExactPath(path) {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.taint[bpf2frame.HashString(path)]&taintWritten != 0
}

// Apply enforces a decision from userspace. Without BPF-LSM the repertoire is
// alert + kill only: Kill terminates the offending process/session; Block
// degrades to the alert already emitted by the pipeline (the operation has
// occurred and cannot be blocked post-hoc). Allow/Audit/Alert take no action.
func (u *UserspaceEnforcer) Apply(sess *types.AgentSession, d types.Decision, ev *types.SyscallEvent) error {
	switch d.Effect {
	case types.EffectKill:
		return u.kill(sess, ev, d)
	case types.EffectBlock:
		u.log.Warn("enforce(userspace): Block not enforceable without BPF-LSM; alert only",
			zap.String("policy", d.PolicyName), zap.String("reason", d.Reason))
		return nil
	default:
		return nil
	}
}

func (u *UserspaceEnforcer) kill(sess *types.AgentSession, ev *types.SyscallEvent, d types.Decision) error {
	// Prefer the specific offending process; fall back to the session tree.
	var targets []int32
	if ev != nil && ev.HostPID > 1 {
		targets = append(targets, ev.HostPID)
	}
	if sess != nil {
		for _, p := range append([]int32{sess.RootPID}, sess.Members...) {
			if p > 1 {
				targets = append(targets, p)
			}
		}
	}
	if len(targets) == 0 {
		return nil
	}
	seen := map[int32]struct{}{}
	for _, pid := range targets {
		if _, dup := seen[pid]; dup {
			continue
		}
		seen[pid] = struct{}{}
		if u.dryRun {
			u.log.Info("enforce(userspace): dry-run kill", zap.Int32("pid", pid),
				zap.String("effect", string(d.Effect)), zap.String("reason", d.Reason))
			continue
		}
		if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			u.log.Warn("enforce(userspace): kill failed", zap.Int32("pid", pid), zap.Error(err))
		}
	}
	u.log.Info("enforce(userspace): terminated on policy violation",
		zap.String("effect", string(d.Effect)), zap.String("policy", d.PolicyName),
		zap.String("reason", d.Reason))
	return nil
}

// SelectBackend chooses the enforcement backend. pref is the configured
// enforcerBackend ("auto"|"bpf-lsm"|"apparmor"|"userspace"); lsmList is the
// contents of /sys/kernel/security/lsm.
func SelectBackend(pref, lsmList string, m Maps, dryRun bool, log *zap.Logger) pipeline.Enforcer {
	hasBPF := hasBPFLSM(lsmList)
	switch strings.ToLower(strings.TrimSpace(pref)) {
	case "userspace", "apparmor":
		return NewUserspace(dryRun, log)
	case "bpf-lsm", "bpf":
		if !hasBPF {
			log.Warn("enforcerBackend=bpf-lsm forced but 'bpf' is not in the active LSM list; " +
				"BPF-LSM attach will likely fail")
		}
		return New(m, dryRun, log)
	default: // auto / unset
		if hasBPF {
			return New(m, dryRun, log)
		}
		log.Warn("BPF-LSM unavailable; using userspace (post-hoc kill) enforcement backend")
		return NewUserspace(dryRun, log)
	}
}

// hasBPFLSM reports whether the comma-separated LSM list advertises the bpf LSM.
func hasBPFLSM(lsmList string) bool {
	for _, name := range strings.Split(lsmList, ",") {
		if strings.TrimSpace(name) == "bpf" {
			return true
		}
	}
	return false
}
