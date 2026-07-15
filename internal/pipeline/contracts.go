// SPDX-License-Identifier: Apache-2.0
// Package pipeline defines the contracts every component implements
// (consumer-defined, Go-idiomatic; conformance checked in contracts_test.go).
// Components live in sibling internal/* packages and depend only on pkg/types —
// never on each other; cmd/agentknox wires them together with channels.
package pipeline

import (
	"context"
	"net"

	"github.com/boanlab/agentknox/pkg/policyspec"
	"github.com/boanlab/agentknox/pkg/types"
)

// SystemSensor: loads eBPF, streams decoded+paired+mapped system events.
type SystemSensor interface {
	Start(ctx context.Context) (<-chan types.SyscallEvent, error)
	// RegisterSession tells the kernel to fully monitor/enforce this cgroup.
	RegisterSession(cgroupID uint64)
	UnregisterSession(cgroupID uint64)
	Close() error
}

// SemanticSensor: attaches TLS uprobes per session and streams plaintext chunks.
type SemanticSensor interface {
	Start(ctx context.Context) (<-chan types.SemanticChunk, error)
	// Attach installs uprobes at the resolved offsets for a session process.
	Attach(pid int32, plan *types.AttachPlan) error
	Detach(pid int32) error
	Close() error
}

// Resolver: recovers the plaintext boundary offsets for a process.
type Resolver interface {
	Resolve(pid int32, agent types.AgentKind) (*types.AttachPlan, error)
}

// SemanticParser: reassembles chunks and parses provider/MCP/DB formats.
type SemanticParser interface {
	// Feed pushes a chunk; parsed events (if any) are returned.
	Feed(chunk types.SemanticChunk, sess *types.AgentSession) []types.SemanticEvent
}

// SessionManager: detects agents, normalizes to AgentSession, enriches events.
type SessionManager interface {
	// OnExec inspects an exec event; returns a new session if one was detected.
	OnExec(ev *types.SyscallEvent) (*types.AgentSession, bool)
	// OnExit updates session membership/lifecycle.
	OnExit(ev *types.SyscallEvent)
	// LookupByCgroup returns the owning session for a cgroup id, if any.
	LookupByCgroup(cgroupID uint64) (*types.AgentSession, bool)
	// Enrich attaches session/meta references to a system event in place.
	Enrich(ev *types.SyscallEvent)
	List() []*types.AgentSession
}

// Correlator: fuses semantic intents with system effects.
type Correlator interface {
	// PushSyscall / PushSemantic feed the two streams; correlated actions and
	// graph edges are emitted on the channels returned by Outputs.
	PushSyscall(ev *types.SyscallEvent)
	PushSemantic(ev *types.SemanticEvent)
	Outputs() (<-chan types.CorrelatedAction, <-chan types.GraphEdge)
}

// PolicyEngine: evaluates dual-layer policy.
type PolicyEngine interface {
	Load(policies []*policyspec.Policy) error
	EvaluateSyscall(ev *types.SyscallEvent, sess *types.AgentSession) types.Decision
	EvaluateSemantic(ev *types.SemanticEvent, sess *types.AgentSession) types.Decision
	EvaluateAction(a *types.CorrelatedAction, sess *types.AgentSession) types.Decision
	// KernelRules returns pre-enforceable (system-only) rules for the Enforcer.
	KernelRules() []KernelRule
}

// KernelRule is a compiled, pre-enforceable rule for kernel installation.
type KernelRule struct {
	PolicyName string
	Selector   []string
	Category   types.Category
	Operation  string
	PathPrefix string
	CIDR       string
	DBEngine   string
	DBTable    string
	Effect     types.PolicyEffect
}

// Enforcer: installs kernel enforcement and applies runtime decisions.
type Enforcer interface {
	Backend() string // "bpf-lsm" | "userspace"
	InstallRules(rules []KernelRule) error
	// ClearRules removes previously installed path/dir/network rules (used on
	// policy hot-reload before re-installing). Sessions and taint are preserved.
	ClearRules() error
	// EnforceSession maps a session's cgroup and pid tree into the enforcement domain.
	EnforceSession(sess *types.AgentSession) error
	// PopulateAgentSigs seeds agent-signature hashes so the kernel can arm a newly
	// exec'd agent in-kernel (bpf-lsm backend); a no-op on the userspace backend.
	PopulateAgentSigs(signatures []string)
	// RegisterAgentBinary seeds one resolved worker-binary basename so a symlinked
	// agent's re-exec'd worker (e.g. Bun/Claude's versioned binary) is armed at exec.
	RegisterAgentBinary(name string)
	// EnforcePID scopes enforcement to an additional agent-tree process.
	EnforcePID(pid int32)
	// SetPidEgressDeny fork-propagates a deny-egress flag from a tainting pid, so
	// its exfil-child's connect is refused even in a different cgroup.
	SetPidEgressDeny(pid int32)
	// MarkSensitivePath records an absolute path as a sensitive source so a monitored
	// agent's read-open of it arms deny-egress on the reading pid synchronously
	// in-kernel (io_uring-immune, race-free), independent of the userspace pipeline.
	MarkSensitivePath(path string)
	// SetNetPosture sets/clears deny-all-egress pre-block for a session's cgroup.
	SetNetPosture(cgroupID uint64, denyEgress bool)
	// BlockIP installs an exact egress deny for ip (dynamic runtime block, and the
	// resolved-IP install path for fqdn policy rules). UnblockIP removes it.
	BlockIP(ip net.IP) error
	UnblockIP(ip net.IP) error
	// SetTaintedCodePosture enables blocking exec/read of agent-written code.
	SetTaintedCodePosture(cgroupID uint64, enable bool)
	// SetDenyCode records whether the policy wants agent-written-code execution
	// blocked, so the deny-tainted-code bit is armed in the session flags (fork-
	// propagated) at arming and enforcement rather than as a per-cgroup posture.
	SetDenyCode(enable bool)
	// TaintFile marks an absolute path with provenance taint (agent-written);
	// code=true also flags it as executable code (shebang/exec-bit/extension).
	TaintFile(path string, code bool)
	// TaintPersist marks an absolute path as an agent-registered persistence
	// artifact (cron/systemd/hook) so out-of-tree delayed execution is attributed.
	TaintPersist(path string)
	// IsTaintedWritten reports whether a path is marked agent-written (for the
	// userspace interpreter-script check).
	IsTaintedWritten(path string) bool
	// Apply performs a runtime decision (Block via kernel map, Kill via signal).
	Apply(sess *types.AgentSession, d types.Decision, ev *types.SyscallEvent) error
	Close() error
}

// Exporter: fans events/alerts out to the gRPC stream, WAL, and replay ring.
type Exporter interface {
	EmitSyscall(ev *types.SyscallEvent)
	EmitSemantic(ev *types.SemanticEvent)
	EmitAction(a *types.CorrelatedAction)
	EmitAlert(al *types.Alert)
	EmitEdge(e *types.GraphEdge)
	Start(ctx context.Context) error
	Close() error
}
